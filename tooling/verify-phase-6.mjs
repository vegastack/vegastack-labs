import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { acceptanceScenarioDigest, canonicalJSON, exactKeys, executeAcceptanceScenarios, parseGoScenarioPass, validateAcceptanceDefinition } from './lib/acceptance-scenarios.mjs';
import { packageManagerInvocation, runCommand } from './lib/process.mjs';
import { phase3LinkerFlags } from './verify-phase-3.mjs';
const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const fail=reason=>{throw new Error(`PHASE6_FAILED:${reason}`);};
const statuses=new Set(['passed','failed','pending','pending-deferred']);
function scenario(id,ownerIssue,file,selector,kind='go-test',environment='built-linux') {
  return Object.freeze({id,requirementId:`6.${id}`,ownerIssue,seam:'suite',kind,path:file,selector,environment,proofClass:'fixture',expected:Object.freeze({result:'pass',errorCode:null,state:null}),repeat:1,seed:null,cleanup:'runner-owned-temporary-root',sanitizer:'phase6-private-artifact-scan'});
}
// Independent finite obligations. Shared owning selectors execute once, even
// when they prove several obligations; adding a catalog entry cannot waive one.
export const REQUIRED_PHASE6_SCENARIOS=Object.freeze([
  scenario('setup.first-start-restart',231,'internal/server/local_setup_acceptance_linux_test.go','TestLocalSetupFirstStartAndRestart'),
  scenario('setup.existing-data-preserved',231,'internal/server/local_setup_acceptance_linux_test.go','TestLocalSetupPreflightDenialsPreserveData'),
  scenario('setup.changed-intent-denied',231,'internal/server/local_setup_acceptance_linux_test.go','TestLocalSetupChangedIntentPreservesApproval'),
  scenario('setup.transport-denied',231,'internal/server/local_setup_acceptance_linux_test.go','TestLocalSetupApprovalTransportDenials'),
  scenario('setup.interruption',231,'internal/server/local_setup_acceptance_linux_test.go','TestLocalSetupInitializationInterruption'),
  scenario('setup.exclusive-writer',231,'internal/server/local_setup_acceptance_linux_test.go','TestLocalSetupConcurrentOneWinner'),
  scenario('discovery.approved-pinned-identity',217,'internal/server/host_discovery_acceptance_linux_test.go','TestHostDiscoveryAcceptanceDatabaseAPIApprovalAndSSH'),
  scenario('discovery.unqualified-recovery-denied',217,'internal/server/host_discovery_acceptance_linux_test.go','TestHostDiscoveryAcceptanceUnqualifiedRecovery'),
  scenario('discovery.preloaded-key-current-revocation',224,'internal/server/host_discovery_preloaded_acceptance_linux_test.go','TestPreloadedDiscoveryAPIApprovalAndRevocation'),
  scenario('discovery.preloaded-key-denials',224,'internal/server/host_discovery_preloaded_acceptance_linux_test.go','TestPreloadedDiscoveryAPIDenialsBeforeConnection'),
  scenario('adoption.inert-registration',222,'internal/server/host_adoption_acceptance_linux_test.go','TestHostAdoptionAcceptanceHasNoExternalAction'),
  scenario('adoption.identity-denials',222,'internal/server/host_adoption_acceptance_linux_test.go','TestHostAdoptionAcceptanceDenials'),
  scenario('action.exact-authority',223,'internal/server/host_action_acceptance_linux_test.go','TestHostActionAcceptance'),
  scenario('action.durable-replay',223,'internal/hostaction/host_action_process_test.go','TestHostActionProcessCrashAndDurableReplay','go-test','fixture'),
  scenario('action.concurrent-claim',223,'internal/hostaction/host_action_process_test.go','TestHostActionProcessConcurrentClaim','go-test','fixture'),
  scenario('action.persistence-failures',223,'internal/hostaction/host_action_process_test.go','TestHostActionProcessPersistenceFailures','go-test','fixture'),
  scenario('action.invalid-frames',223,'internal/hostaction/host_action_process_test.go','TestHostActionProcessRejectsBadFrames','go-test','fixture'),
  scenario('action.interrupted-transport',223,'internal/hostaction/host_action_process_test.go','TestHostActionProcessInterruptedTransport','go-test','fixture'),
  scenario('credential.restart-lifecycle',223,'internal/server/native_restart_acceptance_linux_test.go','TestNativeRestartLifecycleAcceptance'),
  ...['accounts','ssh','firewall','rollback','allowed-source','denied-source','container-path'].map(control=>scenario(`access.${control}`,225,'internal/server/host_access_acceptance_linux_test.go','TestHostAccessSequenceAcceptance')),
  scenario('baseline.time-approved-pipeline',226,'internal/server/host_baseline_acceptance_linux_test.go','TestHostBaselineAcceptance'),
  scenario('baseline.fail2ban',226,'internal/debianbaseline/controls_test.go','TestFail2banRequiresExactObservedSourcesAndBounds','go-test','fixture'),
  scenario('baseline.audit',226,'internal/debianbaseline/controls_test.go','TestAuditRequiresActiveBoundedNativeState','go-test','fixture'),
  scenario('baseline.apparmor',226,'internal/debianbaseline/controls_test.go','TestAppArmorRequiresPinnedEnforcingProfile','go-test','fixture'),
  scenario('baseline.aide',226,'internal/debianbaseline/aide_native_test.go','TestAIDERefreshRequiresExactPriorDatabase','go-test','fixture'),
  scenario('baseline.updates',226,'internal/debianbaseline/apt_test.go','TestUpdateProofRequiresActualSignedSnapshotPackageJoin','go-test','fixture'),
  scenario('baseline.resources-kernel',226,'internal/debianbaseline/phase6_health_acceptance_test.go','TestPhase6ResourceKernelObservation','go-test','fixture'),
  scenario('baseline.missing-controls',226,'internal/debianbaseline/controls_test.go','TestCollectorRetainsMissingRequiredControls','go-test','fixture'),
  scenario('volume.mapping',226,'internal/debianbaseline/volume_mapping_test.go','TestVolumeGeometryJoinsHeaderToActiveMapping','go-test','fixture'),
  scenario('volume.recovery-key',226,'internal/debianbaseline/volume_recovery_unix_test.go','TestVolumeRecoveryPrivateFilesAndObservedResult','go-test','fixture'),
  scenario('volume.wrong-key-header',226,'internal/debianbaseline/volume_recovery_unix_test.go','TestVolumeRecoveryRejectsHeaderChangeAndFailedKey','go-test','fixture'),
  scenario('volume.two-current-receipts',226,'internal/store/host_storage_prerequisites_test.go','TestHostStorageRequiresExactTwoCurrentReceipts','go-test','fixture'),
  scenario('volume.subject-custodian-authority',226,'internal/store/host_storage_prerequisites_test.go','TestBaselineScopeUsesCanonicalSubjectRoleAuthorization','go-test','fixture'),
  scenario('admission.registration-not-security',229,'internal/api/host_admission_integration_linux_test.go','TestHostAdmissionAPIRegistrationDoesNotAdmit'),
  scenario('admission.current-proof-invalidation',229,'internal/api/host_admission_integration_linux_test.go','TestHostAdmissionAPICurrentProofAndInvalidation'),
  scenario('admission.independent-common-matrix',229,'internal/gate/host_requirements_test.go','TestHostRequiredControlsIndependentCommonMatrix','go-test','fixture'),
  scenario('admission.exact-platform',229,'internal/gate/host_requirements_test.go','TestHostRequiredControlsExactPlatformOnly','go-test','fixture'),
  scenario('admission.independent-role-matrix',229,'internal/gate/host_requirements_test.go','TestHostRequiredRoleControlsIndependentMatrix','go-test','fixture'),
  scenario('role.control-handoff-data-preserved',230,'internal/linuxrole/control_handoff_linux_test.go','TestControlHandoffFailuresPreserveDatabaseAndRequireRecovery'),
  scenario('role.control-handoff-disconnected-caller',230,'internal/linuxrole/control_handoff_linux_test.go','TestControlHandoffWorkerSurvivesDisconnectedCaller'),
  scenario('role.control-handoff-current-authority',230,'internal/linuxrole/native_control_observation_linux_test.go','TestNativeHandoffObservationRequiresFreshSameAuthority'),
  scenario('role.approved-foundation',230,'internal/api/host_role_acceptance_linux_test.go','TestLinuxRoleApprovedPipeline'),
  scenario('replacement.approved-freeze-alias',233,'internal/api/host_replacements_integration_linux_test.go','TestReplacementAPIClaimAndFreezeApprovedPipeline'),
  scenario('replacement.current-role-admission',233,'internal/api/host_replacements_integration_linux_test.go','TestReplacementPersistedRoleAdmission'),
  scenario('surface.real-server-linked-replacement',239,'internal/api/host_lifecycle_browser_pipeline_linux_test.go','TestHostLifecycleBrowserLinkedReplacementPipeline'),
  scenario('surface.cli-human-json-equivalence',232,'internal/cli/hosts_transport_linux_test.go','TestNodeOutputParityUsesSameServerFacts'),
  scenario('surface.built-cli-authority',232,'internal/server/node_cli_acceptance_linux_test.go','TestNodeCLIDiscoveryAdoptionInspection'),
  scenario('authorization.approved-grant-batch',247,'internal/api/authorization_grants_linux_test.go','TestGrantBatchApprovedAPIFromInitialSetup'),
  scenario('surface.inert-stale-plan',239,'web/e2e/host-lifecycle.spec.ts','preloaded target remains inert and stale plan clears prior forms','browser-test','chromium'),
  scenario('provider.handoff-prerequisites-visible',230,'web/e2e/host-lifecycle.spec.ts','role import stays inert and shows independent admission prerequisites','browser-test','chromium'),
  scenario('surface.role-prerequisites',239,'web/e2e/host-lifecycle.spec.ts','role import stays inert and shows independent admission prerequisites','browser-test','chromium'),
  scenario('surface.baseline-not-role-admission',239,'web/e2e/host-lifecycle.spec.ts','baseline success does not replace blocked or stale role admission','browser-test','chromium'),
  scenario('surface.replacement-impact',239,'web/e2e/host-replacement.spec.ts','replacement preview preserves both identities and needs separate impact confirmation','browser-test','chromium'),
  scenario('surface.partial-not-ownership',239,'web/e2e/host-replacement.spec.ts','replacement source and partial verification never imply committed ownership','browser-test','chromium'),
  scenario('surface.plan-race',239,'web/e2e/host-plan-race.spec.ts','delayed plan for draft A cannot attach beneath newer policy draft B','browser-test','chromium'),
]);
export const PHASE6_NATIVE_SCENARIOS=Object.freeze(['baseline-access','baseline-controls','access-idempotence','access-rollback-timeout','access-rollback-reboot','action-replay','action-concurrency','fail2ban-window','container-network','volume-effective-mapping','volume-recovery-positive','volume-wrong-key','volume-wrong-header','volume-wrong-slot','volume-wrong-mapping','volume-revoked-binding','volume-unchanged-after-verification','volume-inconsistent-redundant-header','volume-status-no-original-repair','volume-sealed-copy-write-refused','native-credential-lifecycle','control-setup','control-handoff','role-application','role-ci','role-reserve','replacement-recovery']);
export function aggregatePhase6(results={}) {
  const keys=['linuxSoftware','linuxNative','macSoftware','macNative','operatorAcceptance'];
  if(!results || typeof results!=='object' || Object.keys(results).some(k=>!keys.includes(k)))fail('status');
  const resolved=Object.fromEntries(keys.map(k=>[k,results[k]??(k==='linuxNative'||k.startsWith('mac')?'pending-deferred':'pending')]));
  if(Object.values(resolved).some(v=>!statuses.has(v)))fail('status');
  const fullPhase=Object.values(resolved).includes('failed')?'failed':Object.values(resolved).every(v=>v==='passed')?'passed':'pending';
  return {...resolved,fullPhase,fleetActivation:'pending'};
}
export function validatePhase6Definition(definition) {
  if(!exactKeys(definition,['schemaVersion','scenarios'])||definition.schemaVersion!==1||canonicalJSON(definition.scenarios)!==canonicalJSON(REQUIRED_PHASE6_SCENARIOS))fail('definition');
  return true;
}
const PRIVATE=/(?:VSK_PRIVATE_CANARY|phase6-private-canary|-----BEGIN [A-Z ]*PRIVATE KEY-----|authorization\s*:\s*bearer|\bbearer\s+\S+|\b(?:gh[opsu]_|github_pat_)[A-Za-z0-9_]+|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|(?:\/home\/|\/Users\/)[^\s"']*(?:control\.db|credential|private)|\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+(?:\.\d+)?\b)/i;
export function scanPhase6Captured(value) {
  const texts=typeof value==='string'?[value]:[value?.stdout,value?.stderr];
  if(texts.some(v=>typeof v!=='string'||Buffer.byteLength(v)>1048576||PRIVATE.test(v)))fail('evidence-sanitizer');
  return true;
}
export async function phase6Definitions(root=ROOT) {
  const [definition,evidence]=await Promise.all([readFile(path.join(root,'tooling/testdata/phase-6/acceptance-scenarios.json'),'utf8').then(JSON.parse),readFile(path.join(root,'tooling/phase-6-evidence.json'),'utf8').then(JSON.parse)]);
  validatePhase6Definition(definition);
  await validateAcceptanceDefinition({root,phase:6,definition,evidence,requiredScenarios:REQUIRED_PHASE6_SCENARIOS});
  return {definition,evidence};
}
export async function phase6SourceState(root=ROOT) {
  const [head,status]=await Promise.all([runCommand('git',['rev-parse','HEAD'],{cwd:root,capture:true}),runCommand('git',['status','--porcelain=v1','--untracked-files=all'],{cwd:root,capture:true})]);
  if(!/^[a-f0-9]{40}$/.test(head.stdout.trim())||status.stdout.trim())fail('source-dirty');
  return head.stdout.trim();
}
export function phase6GoFailure(error,selectors) {
  const known=new Set(REQUIRED_PHASE6_SCENARIOS.filter(s=>s.kind==='go-test').map(s=>s.selector));
  const failed=new Set();
  for(const line of (typeof error?.stdout==='string'?error.stdout.slice(0,1048576):'').split('\n')) {
    try {const event=JSON.parse(line);if(event.Action==='fail'&&known.has(event.Test)&&selectors.includes(event.Test))failed.add(event.Test);}catch {}
  }
  return Object.assign(new Error('PHASE6_FAILED:go-command',{cause:error}),{phase6Failure:{stage:'go-test',failedSelectors:selectors.filter(s=>known.has(s)&&failed.has(s)),exitCode:Number.isInteger(error?.code)&&error.code>=0&&error.code<=255?error.code:null,timedOut:error?.timedOut===true}});
}
export async function executePhase6Scenarios(root,definition,{runtime,artifactRoot}) {
  const groups=new Map(),outcomes=[];
  for(const s of definition.scenarios.filter(s=>s.kind==='go-test')){
    if(s.environment==='built-linux'&&process.platform!=='linux'){outcomes.push({id:s.id,environment:s.environment,status:'linux-required'});continue;}
    const pkg=path.dirname(s.path);if(!groups.has(pkg))groups.set(pkg,[]);groups.get(pkg).push(s);
  }
  for(const [pkg,scenarios] of groups){
    const selectors=[...new Set(scenarios.map(s=>s.selector))];
    // API lifecycle cases own independent temporary stores and ephemeral sockets.
    // Two finite batches bound the long package without repeating any selector.
    const batches=(pkg==='internal/api'?[selectors.filter((_,i)=>i%2===0),selectors.filter((_,i)=>i%2===1)]:[selectors]).filter(batch=>batch.length);
    const results=await Promise.allSettled(batches.map(batch=>runCommand('go',['test','-json','-race','-count=1',`./${pkg}`,'-run',`^(${batch.join('|')})$`],{cwd:root,capture:true,timeoutMs:600000,env:{...process.env,...(runtime?{VSK_PHASE3_BINARY:runtime.binary,VSK_PHASE3_RUNTIME_ROOT:runtime.root,VSK_NODE_CLI_BINARY:runtime.binary}:{})}})));
    // Always join both children before returning, including failure and cleanup.
    for(let i=0;i<results.length;i++){const result=results[i];if(result.status==='rejected')throw phase6GoFailure(result.reason,batches[i]);scanPhase6Captured(result.value);for(const selector of batches[i])parseGoScenarioPass(result.value.stdout,selector,1,6);}
    for(const s of scenarios)outcomes.push({id:s.id,environment:s.environment,status:'pass'});
  }
  outcomes.push(...await executeAcceptanceScenarios({root,phase:6,definition:{schemaVersion:1,scenarios:definition.scenarios.filter(s=>s.kind!=='go-test')},runtime,artifactRoot,scanCaptured:scanPhase6Captured}));
  return definition.scenarios.map(s=>outcomes.find(o=>o.id===s.id));
}
export async function runPhase6(root=ROOT) {
  const sourceCommit=await phase6SourceState(root),startedAt=new Date().toISOString();
  const {definition}=await phase6Definitions(root);
  const build=packageManagerInvocation(['--filter','@vegastack/labs-web','build']);
  scanPhase6Captured(await runCommand(build.command,build.args,{cwd:root,capture:true,timeoutMs:180000}));
  const artifactRoot=await mkdtemp(path.join(tmpdir(),'vsk-phase6-'));
  let runtime,report;
  try {
    if(process.platform==='linux') {
      const binary=path.join(artifactRoot,'vsk-labs'),osRelease=path.join(artifactRoot,'os-release');
      await writeFile(osRelease,'ID=debian\nVERSION_ID=13\n',{mode:0o600});
      scanPhase6Captured(await runCommand('go',['build','-race','-ldflags',phase3LinkerFlags({database:path.join(artifactRoot,'control.db'),osRelease}),'-o',binary,'./cmd/vsk-labs'],{cwd:root,capture:true,timeoutMs:180000}));
      runtime={root:artifactRoot,binary};
    }
    const outcomes=await executePhase6Scenarios(root,definition,{runtime,artifactRoot});
    if(await phase6SourceState(root)!==sourceCommit)fail('source-drift');
    const linuxSoftware=outcomes.every(o=>o.status==='pass')?'passed':'pending';
    report={schema:'vegastack-labs.dev/phase6-software',schemaVersion:1,proofClass:'fixture',sourceCommit,scenarioDigest:acceptanceScenarioDigest(definition),startedAt,finishedAt:new Date().toISOString(),cleanup:'passed',outcomes,...aggregatePhase6({linuxSoftware})};
  } finally {await rm(artifactRoot,{recursive:true,force:true});}
  report.cleanupFinishedAt=new Date().toISOString();return report;
}
if(process.argv[1]===fileURLToPath(import.meta.url)) {
  try {if(process.argv.length!==2)fail('arguments');const report=await runPhase6();process.stdout.write(`${JSON.stringify(report)}\n`);process.exitCode=report.linuxSoftware==='passed'?0:2;}
  catch(error) {process.stderr.write('PHASE6_FAILED:verification\n');if(error?.phase6Failure)process.stderr.write(`${JSON.stringify(error.phase6Failure)}\n`);process.exitCode=1;}
}
