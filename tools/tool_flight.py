"""Live companion-tool flight. Does NOT activate Titan or invent learner data.
Run after building the three Rust tools. All outputs go outside target repositories.
"""
from pathlib import Path
import datetime, hashlib, json, os, shutil, subprocess, sys

campaign=Path(__file__).resolve().parents[3]
repos=campaign/'repos'
out=campaign/'evidence'/('tool-flight-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S'))
out.mkdir(parents=True)
env=dict(os.environ,TEMP=str(campaign/'tmp'),TMP=str(campaign/'tmp'))
tsx=repos/'spc-remediation/node_modules/tsx/dist/cli.mjs'
spc=['node',str(tsx),str(repos/'spc-remediation/src/cli.ts')]
oracle=['node',str(tsx),str(repos/'ruleforge-engine/src/cli/oracle-cli.ts')]
ef=str(campaign/'build/evidence-forge/debug/evidence-forge.exe')
fr=str(campaign/'build/flight-recorder/debug/flight-recorder.exe')
lt=str(campaign/'build/learning-trace/debug/learning-trace.exe')
subject=repos/'ruleforge-engine'
observed=[]

def run(name,args,expect_success=True,cwd=subject):
    result=subprocess.run([str(a) for a in args],cwd=cwd,env=env,capture_output=True,timeout=60)
    (out/(name+'.stdout')).write_bytes(result.stdout)
    (out/(name+'.stderr')).write_bytes(result.stderr)
    record={'name':name,'command':[str(a) for a in args],'cwd':str(cwd),'exit':result.returncode,'expected_success':expect_success,'finding':'PASS' if (result.returncode==0)==expect_success else 'FAIL'}
    observed.append(record)
    (out/'commands.json').write_text(json.dumps(observed,indent=2),encoding='utf-8')
    if record['finding']=='FAIL': raise RuntimeError(f'{name}: unexpected exit {result.returncode}: {result.stderr.decode("utf-8",errors="replace")}')
    return result.stdout.decode('utf-8',errors='replace')

revision=run('subject-revision',['git','rev-parse','HEAD']).strip()
request={'interopVersion':'1.0.0','projectIdentity':{'projectId':'ruleforge-live-flight','projectName':'RuleForge simulation engine','commitSha':revision},'executionIntent':'Verify deterministic simulation replay and invariant preservation with bounded local tests. No deployment or promotion.'}
(out/'request.json').write_text(json.dumps(request),encoding='utf-8')
contract=json.loads(run('preflight',spc+['titan-compile',out/'request.json']))
assert contract['success'] and contract['contract']['authorityEnvelope']['canPromoteToProduction'] is False
assert contract['contract']['identity']['commitSha']==revision
bad=dict(request,interopVersion='unsupported')
(out/'invalid-request.json').write_text(json.dumps(bad),encoding='utf-8')
run('preflight-invalid',spc+['titan-compile',out/'invalid-request.json'],False)
bad=dict(request,architectureDocs=[{'title':'A','path':'a.md','content':'Database layer must use postgres exclusively.','authority':'CANONICAL','hash':hashlib.sha256(b'A').hexdigest()},{'title':'B','path':'b.md','content':'Database layer must use mongodb exclusively.','authority':'CANONICAL','hash':hashlib.sha256(b'B').hexdigest()}])
(out/'contradictory-request.json').write_text(json.dumps(bad),encoding='utf-8')
run('preflight-contradictory',spc+['titan-compile',out/'contradictory-request.json'],False)

session=out/'recorder'
run('recorder-init',[fr,'init','--dir',session,'--project','ruleforge-live-flight','--repo-path',subject,'--tester','Codex self-test','--objective','Capture actual companion execution; Titan operational authority remains blocked','--limitations','No independent qualification; no live Titan orchestration'])
run('record-contract',[fr,'artifact','--dir',session,'--file',out/'preflight.stdout','--label','Prepared specification','--kind','diagnostic-output'])
run('record-start',[fr,'event','--dir',session,'--kind','action','--provenance','machine','--description','Execute RuleForge engine under Evidence Forge; this is a self-test'])

def config(name,command,args):
    p=out/(name+'.toml')
    # JSON strings and arrays are valid TOML basic string/array values here.
    p.write_text('name='+json.dumps(name)+'\n[[steps]]\nid="execute"\ncommand='+json.dumps(command)+'\nargs='+json.dumps([str(a) for a in args])+'\ntimeout_secs=30\n',encoding='utf-8')
    return p

oracle_out=out/'oracle'
cfg=config('live-oracle',oracle[0],oracle[1:]+['run','--target','ruleforge','--seed','1337','--steps','12','--out',oracle_out,'--json'])
package=out/'evidence-package'
run('evidence-execute',[ef,'run',subject,'--config',cfg,'--output',package,'--strict'])
run('evidence-verify',[ef,'verify',package])
report=json.loads((oracle_out/'report.json').read_text(encoding='utf-8'))
assert report['verdict']=='PASS' and report['totalTransitionsAudited']>0
run('oracle-package-verify',oracle+['verify-package',oracle_out])
run('oracle-replay',oracle+['replay','--target','ruleforge','--seed','1337'])
run('oracle-resume',oracle+['resume','--target','ruleforge','--seed','1337'])
broken=out/'deliberately-broken-reference'
run('broken-reference-rejected',oracle+['run','--target','broken','--seed','42','--steps','8','--out',broken],False)
reproducers=list((broken/'reproducers').glob('*.json'))
assert reproducers, 'Broken reference must yield an actually reproduced failure'
minimized=json.loads(run('minimize-reproduced-failure',oracle+['minimize',reproducers[0],'--target','broken']))
assert minimized['minimizedSequenceLength']<=minimized['originalSequenceLength']
run('minimize-wrong-target-rejected',oracle+['minimize',reproducers[0],'--target','corrected'],False)
run('oracle-unknown-target',oracle+['run','--target','unknown','--out',out/'must-not-exist'],False)
assert not (out/'must-not-exist').exists()
run('record-evidence',[fr,'artifact','--dir',session,'--file',package/'evidence.json','--label','Evidence Forge live result','--kind','diagnostic-output'])
run('record-oracle',[fr,'artifact','--dir',session,'--file',oracle_out/'report.json','--label','Oracle live engine report','--kind','diagnostic-output'])

for name in ['corrupt','missing']:
    altered=out/('package-'+name);shutil.copytree(package,altered)
    if name=='corrupt': (altered/'evidence.json').write_text('{}',encoding='utf-8')
    else: (altered/'evidence.json').unlink()
    run('reject-'+name+'-evidence',[ef,'verify',altered],False)
failure=out/'failed-execution'
cfg=config('failing-command',sys.executable,['-c','import sys; print("deliberate live failure"); sys.exit(7)'])
run('failed-execution',[ef,'run',subject,'--config',cfg,'--output',failure],False)
run('failed-execution-evidence-valid',[ef,'verify',failure])
run('record-failure',[fr,'event','--dir',session,'--kind','error','--provenance','machine','--description','Deliberate process exit 7 was rejected; inspect failed-execution evidence'])
run('recorder-interrupt',[fr,'interrupt','--dir',session,'--reason','Exercise explicit interrupted workflow boundary'])
run('recorder-recover',[fr,'recover','--dir',session])

# The recovered Learning Trace schema accepts learner assessments, not process
# outcomes. Exercise this boundary rather than fabricate a learner or mastery.
(out/'software-outcome.jsonl').write_text(json.dumps({'run_id':'live-flight','process_exit':7})+'\n',encoding='utf-8')
run('learning-trace-rejects-software-outcome',[lt,'validate',out/'software-outcome.jsonl'],False)
run('record-learning-boundary',[fr,'event','--dir',session,'--kind','note','--provenance','machine','--description','Learning Trace rejected software outcome schema; no learner efficacy was inferred'])
run('recorder-complete',[fr,'complete','--dir',session,'--outcome','Tool flight captured with deliberate failure; full Titan workflow remains blocked'])
run('recorder-validate',[fr,'validate','--dir',session])
run('recorder-report',[fr,'report','--dir',session])
run('recorder-export',[fr,'export-titan','--dir',session,'--output',out/'titan-recorder-packet.json'])
packet=json.loads((out/'titan-recorder-packet.json').read_text(encoding='utf-8'))
assert packet['release_promotion_authorized'] is False
assert packet['typed_status']!='completed_clean'
summary={'partial_live_tool_exchange':'PASS','full_titan_five_tool_workflow':'BLOCKED','independent_qualification':'NOT VERIFIED','release':'NOT RELEASE QUALIFIED','subject_revision':revision,'blockers':['Titan operational Root and orchestration are not implemented/authorized by fixture records','Learning Trace supports learner assessments, not software decision traces'],'commands':len(observed)}
(out/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
hashes={str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest() for p in out.rglob('*') if p.is_file()}
(out/'SHA256.json').write_text(json.dumps(hashes,indent=2),encoding='utf-8')
print(json.dumps({'output':str(out),**summary},indent=2))
