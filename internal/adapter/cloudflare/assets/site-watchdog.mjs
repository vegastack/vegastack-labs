// Versioned scheduled Worker artifact. Deployment/configuration is separately gated.
export const CRON = '*/5 * * * *';
export const STALE_MS = 15 * 60_000;
const MAX_ATTEMPTS = 6;
const KEYS = ['schema','schemaVersion','siteDigest','observedAt','stateRevision','recoveryEpoch'].sort();
const fail = code => Object.assign(new Error(code), {code});
const safeCode = error => ['github-unavailable','github-ambiguous','github-create-uncertain','secondary-unavailable','state-unavailable','heartbeat-unavailable'].includes(error?.code) ? error.code : 'checker-unavailable';
function config(env) {
  if (typeof env.GITHUB_TOKEN!=='string'||env.GITHUB_TOKEN.length>4096||typeof env.SLACK_WEBHOOK!=='string'||env.SLACK_WEBHOOK.length>512||typeof env.GITHUB_REPOSITORY!=='string'||env.GITHUB_REPOSITORY.length>201||env.GITHUB_REPOSITORY.split('/').some(part=>['.','..'].includes(part)))throw fail('checker-unavailable');
  if (!/^sha256:[a-f0-9]{64}$/.test(env.SITE_DIGEST) || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPOSITORY) || !env.GITHUB_TOKEN || !env.STATUS?.get || !env.STATUS?.put) throw fail('checker-unavailable');
  let webhook; try { webhook = new URL(env.SLACK_WEBHOOK); } catch { throw fail('secondary-unavailable'); }
  if (webhook.protocol !== 'https:' || webhook.hostname !== 'hooks.slack.com' || webhook.port || webhook.username || webhook.password || webhook.search || webhook.hash || !/^\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+$/.test(webhook.pathname)) throw fail('secondary-unavailable');
}
export function parseHeartbeat(raw, now, siteDigest, uploadedAt = now) {
  if (typeof raw !== 'string' || raw.length > 1024) throw fail('heartbeat-unavailable');
  let heartbeat; try { heartbeat = JSON.parse(raw); } catch { throw fail('heartbeat-unavailable'); }
  if (!heartbeat || Object.keys(heartbeat).sort().join() !== KEYS.join() || heartbeat.schema !== 'vegastack-labs.dev/site-heartbeat' || heartbeat.schemaVersion !== '1.0.0' || heartbeat.siteDigest !== siteDigest || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(heartbeat.observedAt) || !Number.isSafeInteger(heartbeat.stateRevision) || heartbeat.stateRevision < 0 || !Number.isSafeInteger(heartbeat.recoveryEpoch) || heartbeat.recoveryEpoch < 0) throw fail('heartbeat-unavailable');
  const observed = Date.parse(heartbeat.observedAt);
  if (!Number.isFinite(observed) || new Date(observed).toISOString().replace('.000Z','Z') !== heartbeat.observedAt || observed > now || uploadedAt > now || uploadedAt < observed || now-observed >= STALE_MS || now-uploadedAt >= STALE_MS) throw fail('heartbeat-unavailable');
  return {...heartbeat, observed};
}
async function request(fetcher, url, options, expected) {
  let response;
  try { response = await fetcher(url, {...options, redirect:'error', signal:AbortSignal.timeout(5000)}); } catch { throw fail('github-unavailable'); }
  if (!expected.includes(response.status)) {
    const error=fail('github-unavailable');
    error.definitelyRejected = [400,401,403,404,410,422,429].includes(response.status);
    const retry=Number(response.headers?.get('Retry-After'));
    if (Number.isFinite(retry) && retry>0) error.retryAfter=Math.min(retry*1000,30*60_000);
    throw error;
  }
  return response;
}
async function boundedText(response, maximum) {
  if(!response.body?.getReader)throw fail('github-unavailable');
  const reader=response.body.getReader();const decoder=new TextDecoder();let text='',bytes=0;
  try{for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>maximum){await reader.cancel();throw fail('github-unavailable');}text+=decoder.decode(value,{stream:true});}return text+decoder.decode();}finally{reader.releaseLock();}
}
async function boundedJSON(response) {
  const body=await boundedText(response,256*1024);
  try { return JSON.parse(body); } catch { throw fail('github-unavailable'); }
}
async function secondary(env, fetcher, status, code) {
  const text=`VegaStack site watchdog ${env.SITE_DIGEST}: ${status}; ${code}. Inspect the protected watchdog state and approved incident runbook.`;
  let response;try{response=await fetcher(env.SLACK_WEBHOOK,{method:'POST',redirect:'error',signal:AbortSignal.timeout(5000),headers:{'Content-Type':'application/json'},body:JSON.stringify({text})});}catch{throw fail('secondary-unavailable');}
  if(response.status!==200){const error=fail('secondary-unavailable');const retry=Number(response.headers?.get('Retry-After'));if(Number.isFinite(retry)&&retry>0)error.retryAfter=Math.min(retry*1000,30*60_000);throw error;}
  if(await boundedText(response,16)!=='ok')throw fail('secondary-unavailable');
}
function freshState(env){return {schemaVersion:1,siteDigest:env.SITE_DIGEST,leaseUntil:0,lastCheckAt:0,desired:'recovered',openedAt:0,issueNumber:0,createPending:false,lastEpoch:0,lastRevision:0,attempts:0,nextAttemptAt:0,secondaryKey:'',secondaryAttempts:0,secondaryNextAt:0,lastPrimaryCode:'none',lastOutcome:'unobserved'};}
function validateState(state, env) {
  const expected=Object.keys(freshState(env)).sort().join();
  if(!state || Object.keys(state).sort().join()!==expected || state.schemaVersion!==1 || state.siteDigest!==env.SITE_DIGEST || !['recovered','silence'].includes(state.desired) || typeof state.createPending!=='boolean' || typeof state.secondaryKey!=='string' || state.secondaryKey.length>128 || !['unobserved','silence','recovered','github-unavailable','github-ambiguous','github-create-uncertain','secondary-unavailable','checker-unavailable','state-unavailable'].includes(state.lastOutcome)) throw fail('state-unavailable');
  if(!['none','github-unavailable','github-ambiguous','github-create-uncertain','checker-unavailable'].includes(state.lastPrimaryCode))throw fail('state-unavailable');
  for(const key of ['leaseUntil','lastCheckAt','openedAt','issueNumber','lastEpoch','lastRevision','attempts','nextAttemptAt','secondaryAttempts','secondaryNextAt']) if(!Number.isSafeInteger(state[key]) || state[key]<0) throw fail('state-unavailable');
  if(!['','silence','recovered','primary-failed:github-unavailable','primary-failed:github-ambiguous','primary-failed:github-create-uncertain','primary-failed:checker-unavailable'].includes(state.secondaryKey))throw fail('state-unavailable');
  if(state.attempts>MAX_ATTEMPTS || state.secondaryAttempts>MAX_ATTEMPTS)throw fail('state-unavailable');
}
async function reconcileIssue(env, state, fetcher, save) {
  const marker=`<!-- vsk-site-silence:${env.SITE_DIGEST} -->`;
  const base=`https://api.github.com/repos/${env.GITHUB_REPOSITORY}/issues`;
  const headers={'Accept':'application/vnd.github+json','Authorization':`Bearer ${env.GITHUB_TOKEN}`,'X-GitHub-Api-Version':'2026-03-10','User-Agent':'vsk-labs-site-watchdog','Content-Type':'application/json'};
  let matches=[], exhausted=false;
  for(let page=1;page<=3;page++){
    const items=await boundedJSON(await request(fetcher,`${base}?state=all&per_page=100&page=${page}`,{headers},[200]));
    if(!Array.isArray(items))throw fail('github-unavailable');
    matches.push(...items.filter(item=>!item.pull_request && typeof item.body==='string' && item.body.split('\n').includes(marker)));
    if(items.length<100){exhausted=true;break;}
  }
  if(!exhausted || matches.length>1) throw fail('github-ambiguous');
  const issue=matches[0];
  if(issue && (!Number.isSafeInteger(issue.number)||issue.number<1))throw fail('github-ambiguous');
  if(issue){
    state.issueNumber=issue.number;state.createPending=false;
    const wanted=state.desired==='silence'?'open':'closed';
    if(issue.state!==wanted){
      const updated=await boundedJSON(await request(fetcher,`${base}/${issue.number}`,{method:'PATCH',headers,body:JSON.stringify({state:wanted})},[200]));
      if(updated.number!==issue.number || updated.state!==wanted || typeof updated.body!=='string' || !updated.body.split('\n').includes(marker))throw fail('github-ambiguous');
    }
    return;
  }
  if(state.createPending)throw fail('github-create-uncertain');
  if(state.desired==='recovered')return;
  // Persist uncertainty before POST. A lost response never triggers blind creation.
  state.createPending=true;await save();
  let response;
  try{response=await request(fetcher,base,{method:'POST',headers,body:JSON.stringify({title:'VegaStack site heartbeat stale',body:`${marker}\nClass: site-silence\nSite: ${env.SITE_DIGEST}\nLast check: ${new Date(state.lastCheckAt).toISOString()}\nRecovery closes this issue only after a fresh current-site heartbeat.`})},[201]);}
  catch(error){if(error.definitelyRejected)state.createPending=false;throw error;}
  const created=await boundedJSON(response);
  if(!Number.isSafeInteger(created.number)||created.number<1||created.state!=='open'||typeof created.body!=='string'||!created.body.split('\n').includes(marker))throw fail('github-create-uncertain');
  state.issueNumber=created.number;state.createPending=false;
}

export async function checkSite(env, now=Date.now(), fetcher=fetch) {
  if(!Number.isSafeInteger(now)||now<=0)return {status:'blocked',code:'checker-unavailable'};
  try{config(env);}catch(error){return {status:'blocked',code:safeCode(error)};}
  let state, etag;
  const save=async()=>{
    let object;try{object=await env.STATUS.put('watchdog-state.json',JSON.stringify(state),{onlyIf:etag?{etagMatches:etag}:{etagDoesNotMatch:'*'},httpMetadata:{contentType:'application/json'}});}catch{throw fail('state-unavailable');}
    if(!object)throw fail('state-conflict');etag=object.etag;
  };
  try{
    const object=await env.STATUS.get('watchdog-state.json');
    if(object && object.size>4096)throw fail('state-unavailable');
    state=object?JSON.parse(await object.text()):freshState(env);validateState(state,env);etag=object?.etag;
    if(state.leaseUntil>now || state.lastCheckAt>=now)return {status:'deduplicated',code:'check-already-owned'};
    state.leaseUntil=now+60_000;state.lastCheckAt=now;await save();
  }catch(error){
    if(error?.code==='state-conflict')return {status:'deduplicated',code:'check-already-owned'};
    // Storage outage has no durable dedupe; at most one bounded fallback attempt
    // per scheduled invocation, with no raw exception/object content exposed.
    try{await secondary(env,fetcher,'checker-failed',safeCode(error));}catch{return {status:'failed',code:'secondary-unavailable'};}
    return {status:'failed',code:safeCode(error)};
  }
  let heartbeat=null;
  try{
    const object=await env.STATUS.get('heartbeat.json');
    if(!object || object.size>1024)throw fail('heartbeat-unavailable');
    heartbeat=parseHeartbeat(await object.text(),now,env.SITE_DIGEST,new Date(object.uploaded).getTime());
    if(heartbeat.recoveryEpoch<state.lastEpoch || heartbeat.recoveryEpoch===state.lastEpoch && heartbeat.stateRevision<state.lastRevision || state.openedAt && heartbeat.observed<=state.openedAt)throw fail('heartbeat-unavailable');
  }catch{heartbeat=null;}
  const desired=heartbeat?'recovered':'silence';
  if(desired!==state.desired){state.desired=desired;state.attempts=0;state.nextAttemptAt=0;state.secondaryAttempts=0;state.secondaryNextAt=0;if(desired==='silence')state.openedAt=now;}
  if(heartbeat){state.lastEpoch=heartbeat.recoveryEpoch;state.lastRevision=heartbeat.stateRevision;state.openedAt=0;}
  let primaryCode='none';
  if(state.attempts<MAX_ATTEMPTS && now>=state.nextAttemptAt){
    try{await reconcileIssue(env,state,fetcher,save);state.attempts=0;state.nextAttemptAt=0;state.lastPrimaryCode='none';state.lastOutcome=desired;}
    catch(error){state.attempts++;state.nextAttemptAt=now+Math.max(error.retryAfter||0,Math.min(30*60_000,300_000*2**(state.attempts-1)));primaryCode=safeCode(error);state.lastPrimaryCode=primaryCode;state.lastOutcome=primaryCode;}
  }else if(state.attempts)primaryCode=state.lastPrimaryCode;
  const secondaryKey=primaryCode!=='none'?`primary-failed:${primaryCode}`:desired;
  const secondaryStatus=primaryCode==='none' && state.secondaryKey.startsWith('primary-failed:')?`delivery-recovered:${desired}`:secondaryKey;
  if(state.secondaryKey!==secondaryKey && state.secondaryAttempts<MAX_ATTEMPTS && now>=state.secondaryNextAt){
    try{await secondary(env,fetcher,secondaryStatus,primaryCode);state.secondaryKey=secondaryKey;state.secondaryAttempts=0;state.secondaryNextAt=0;}
    catch(error){state.secondaryAttempts++;state.secondaryNextAt=now+Math.max(error.retryAfter||0,Math.min(30*60_000,300_000*2**(state.secondaryAttempts-1)));state.lastOutcome='secondary-unavailable';}
  }
  if(state.secondaryAttempts>0)state.lastOutcome='secondary-unavailable';
  state.leaseUntil=0;
  try{await save();}catch{return {status:'failed',code:'state-unavailable'};}
  return {status:state.attempts||state.secondaryAttempts?'degraded':'checked',code:state.lastOutcome,attempts:state.attempts,secondaryAttempts:state.secondaryAttempts};
}
export default {
  async scheduled(controller,env,ctx){
    if(controller.cron!==CRON)throw new Error('watchdog schedule mismatch');
    const promise=checkSite(env,Date.now());
    ctx.waitUntil(promise);
    return promise;
  },
  // No public status/administration route; optional projection is out of scope.
  async fetch(){return new Response('Not found',{status:404});}
};
