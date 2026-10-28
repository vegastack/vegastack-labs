import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import worker,{checkSite,parseHeartbeat,CRON,STALE_MS} from '../../internal/adapter/cloudflare/assets/site-watchdog.mjs';
const fixture=await readFile(new URL('../../internal/siteheartbeat/testdata/heartbeat.json',import.meta.url),'utf8');
const sample=JSON.parse(fixture), t0=Date.parse(sample.observedAt);
class Bucket {
 constructor(){this.objects=new Map();this.version=0;}
 async get(key){const v=this.objects.get(key);return v?{...v,text:async()=>v.body,size:v.body.length}:null;}
 async put(key,body,options){const old=this.objects.get(key),condition=options?.onlyIf;if(condition?.etagMatches && old?.etag!==condition.etagMatches || condition?.etagDoesNotMatch==='*'&&old)return null;const value={body,etag:String(++this.version),uploaded:new Date(t0)};this.objects.set(key,value);return value;}
 heartbeat(at,extra={}){this.objects.set('heartbeat.json',{body:JSON.stringify({...sample,observedAt:new Date(at).toISOString().replace('.000Z','Z'),...extra}),etag:'heartbeat',uploaded:new Date(at)});}
}
function setup(){
 const env={STATUS:new Bucket(),SITE_DIGEST:sample.siteDigest,GITHUB_REPOSITORY:'example/alerts',GITHUB_TOKEN:'private-token-canary',SLACK_WEBHOOK:'https://hooks.slack.com/services/TX/BX/secondary-secret-canary'};
 const state={issues:[],posts:0,patches:0,secondary:[],calls:[],githubFails:0,secondaryFails:0};
 const fetcher=async(url,options={})=>{state.calls.push([url,options]);if(url.startsWith('https://hooks.slack.com/')){if(state.secondaryFails-->0)throw Error('secret-webhook-response');state.secondary.push(JSON.parse(options.body));return new Response('ok',{status:200});}if(state.githubFails-->0)return new Response('secret-provider-error',{status:503});if(options.method==='POST'){state.posts++;const body=JSON.parse(options.body);const issue={...body,number:state.posts,state:'open'};state.issues.push(issue);return Response.json(issue,{status:201});}if(options.method==='PATCH'){state.patches++;const issue=state.issues.find(i=>url.endsWith('/'+i.number));Object.assign(issue,JSON.parse(options.body));return Response.json(issue);}return Response.json(state.issues);};
 return {env,state,fetcher};
}
test('Go fixture is accepted and strict parsing denies stale/future/secret/wrong-site payloads',()=>{
 assert.equal(parseHeartbeat(fixture,t0,sample.siteDigest).stateRevision,7);
 for(const raw of [fixture,JSON.stringify({...sample,secret:'private-canary'}),JSON.stringify({...sample,siteDigest:'sha256:'+'b'.repeat(64)})])assert.throws(()=>parseHeartbeat(raw,t0+STALE_MS,sample.siteDigest),/heartbeat-unavailable/);
 assert.throws(()=>parseHeartbeat(fixture,t0-1,sample.siteDigest),/heartbeat-unavailable/);
});
test('silence opens exactly one issue, duplicate checks dedupe, fresh verified recovery closes it',async()=>{
 const {env,state,fetcher}=setup();env.STATUS.heartbeat(t0);
 assert.equal((await checkSite(env,t0+STALE_MS,fetcher)).code,'silence');
 await checkSite(env,t0+STALE_MS,fetcher);await checkSite(env,t0+STALE_MS+300000,fetcher);assert.equal(state.posts,1);
 const recovery=t0+STALE_MS+600000;env.STATUS.heartbeat(recovery);
 assert.equal((await checkSite(env,recovery,fetcher)).code,'recovered');assert.equal(state.issues[0].state,'closed');assert.equal(state.patches,1);
 assert.ok(state.secondary.length>=2);assert.ok(!JSON.stringify(state.secondary).includes('private-token-canary'));
});
test('overlapping scheduled checks acquire one conditional R2 owner',async()=>{
 const {env,state,fetcher}=setup();await Promise.all([checkSite(env,t0+STALE_MS,fetcher),checkSite(env,t0+STALE_MS,fetcher)]);assert.equal(state.posts,1);assert.equal(state.secondary.length,1);
});
test('GitHub outage still delivers secondary, bounded retry later recovers primary',async()=>{
 const {env,state,fetcher}=setup();state.githubFails=1;
 const result=await checkSite(env,t0+STALE_MS,fetcher);assert.equal(result.status,'degraded');assert.equal(state.secondary.length,1);assert.equal(state.posts,0);
 await checkSite(env,t0+STALE_MS+300000,fetcher);assert.equal(state.posts,1);assert.ok(!JSON.stringify(state.secondary).includes('secret-provider-error'));
});
test('secondary outage retries without duplicating the issue and pauses at bounded attempts',async()=>{
 const {env,state,fetcher}=setup();state.secondaryFails=99;
 let last;for(let n=0;n<10;n++)last=await checkSite(env,t0+STALE_MS+n*3600000,fetcher);assert.equal(last.status,'degraded');assert.equal(last.code,'secondary-unavailable');
 const persisted=JSON.parse(env.STATUS.objects.get('watchdog-state.json').body);assert.equal(persisted.secondaryAttempts,6);assert.equal(state.posts,1);assert.equal(state.calls.filter(([url])=>url.startsWith('https://hooks.slack.com/')).length,6);
});
test('malformed or wrong-site heartbeat cannot close an existing alert',async()=>{
 const {env,state,fetcher}=setup();await checkSite(env,t0+STALE_MS,fetcher);env.STATUS.heartbeat(t0+STALE_MS+300000,{secret:'private-canary'});await checkSite(env,t0+STALE_MS+300000,fetcher);assert.equal(state.issues[0].state,'open');assert.equal(state.patches,0);
});
test('scheduled artifact uses five-minute contract and has no public administration route',async()=>{
 assert.equal(CRON,'*/5 * * * *');assert.equal((await worker.fetch()).status,404);const {env,fetcher}=setup();let waited;await assert.rejects(()=>worker.scheduled({cron:'* * * * *',scheduledTime:t0},env,{waitUntil(p){waited=p}}),/schedule mismatch/);
});

test('lost create response is reconciled from its exact marker without a second POST',async()=>{
 const {env,state,fetcher}=setup();let lost=false;
 const ambiguous=async(url,options)=>{const response=await fetcher(url,options);if(options?.method==='POST'&&url.startsWith('https://api.github.com/')&&!lost){lost=true;throw Error('secret-lost-response');}return response;};
 await checkSite(env,t0+STALE_MS,ambiguous);assert.equal(state.posts,1);
 await checkSite(env,t0+STALE_MS+300000,ambiguous);assert.equal(state.posts,1);assert.equal(JSON.parse(env.STATUS.objects.get('watchdog-state.json').body).createPending,false);
});
test('unresolved create uncertainty never blindly retries a second issue',async()=>{
 const {env,state,fetcher}=setup();let attempts=0;
 const ambiguous=async(url,options)=>{if(options?.method==='POST'&&url.startsWith('https://api.github.com/')){attempts++;throw Error('private-uncertain-create');}return fetcher(url,options);};
 await checkSite(env,t0+STALE_MS,ambiguous);const result=await checkSite(env,t0+STALE_MS+300000,ambiguous);assert.equal(attempts,1);assert.equal(result.code,'github-create-uncertain');assert.equal(state.posts,0);
});
test('definite expired credential denial is retryable after protected credential recovery',async()=>{
 const {env,state,fetcher}=setup();let denied=false;
 const expiry=async(url,options)=>{if(options?.method==='POST'&&url.startsWith('https://api.github.com/')&&!denied){denied=true;return new Response('private-token-error',{status:401});}return fetcher(url,options);};
 await checkSite(env,t0+STALE_MS,expiry);await checkSite(env,t0+STALE_MS+300000,expiry);assert.equal(state.posts,1);assert.equal(state.issues.length,1);
});
test('secondary 429 observes Retry-After without duplicate issue creation',async()=>{
 const {env,state,fetcher}=setup();let calls=0;
 const limited=async(url,options)=>{if(url.startsWith('https://hooks.slack.com/')&&++calls===1)return new Response('rate_limited',{status:429,headers:{'Retry-After':'1800'}});return fetcher(url,options);};
 await checkSite(env,t0+STALE_MS,limited);await checkSite(env,t0+STALE_MS+300000,limited);assert.equal(calls,1);await checkSite(env,t0+STALE_MS+1800000,limited);assert.equal(calls,2);assert.equal(state.posts,1);
});
test('R2 checker failure has independent secondary delivery and sanitized fixed results',async()=>{
 const {env,state,fetcher}=setup();env.STATUS.get=async()=>{throw Error('private-bucket-secret');};
 const result=await checkSite(env,t0+STALE_MS,fetcher);assert.equal(state.secondary.length,1);assert.equal(result.code,'checker-unavailable');assert.ok(!JSON.stringify([result,state.secondary]).includes('private-bucket-secret'));
});
test('unselected secondary config blocks without any provider call',async()=>{
 const {env,state,fetcher}=setup();delete env.SLACK_WEBHOOK;assert.equal((await checkSite(env,t0,fetcher)).status,'blocked');assert.equal(state.calls.length,0);
});

test('primary and secondary retries remain separate and bounded during simultaneous outage',async()=>{
 const {env,state,fetcher}=setup();state.githubFails=99;state.secondaryFails=99;let last;
 for(let n=0;n<10;n++)last=await checkSite(env,t0+STALE_MS+n*3600000,fetcher);
 const saved=JSON.parse(env.STATUS.objects.get('watchdog-state.json').body);assert.equal(saved.attempts,6);assert.equal(saved.secondaryAttempts,6);assert.equal(last.status,'degraded');assert.equal(state.posts,0);
});
