"""Reproduce all component self-tests without hiding environment failures."""
from pathlib import Path
import datetime,json,os,subprocess
campaign=Path(__file__).resolve().parents[3]
repos=campaign/'repos'
env=dict(os.environ,TEMP=str(campaign/'tmp'),TMP=str(campaign/'tmp'))
Path(env['TEMP']).mkdir(exist_ok=True)
tsx=repos/'spc-remediation/node_modules/tsx/dist/cli.mjs'
summary=[]
for name in ['titan-forward','spc-remediation','ruleforge-engine','evidence-forge','learning-trace','flight-recorder']:
    repo=repos/name
    rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
    dirty=subprocess.check_output(['git','--work-tree=.','status','--porcelain'],cwd=repo,text=True).strip()
    if name=='spc-remediation': commands=[['node',str(tsx),'src/cli.ts','test:all'],['node',str(tsx),'src/core/tests/completionRegressions.ts']]
    elif name=='ruleforge-engine': commands=[['node',str(tsx),'test/oracle-tests.ts'],['node',str(tsx),'test/completion-regressions.ts']]
    else: commands=[['cargo','test','--locked','--offline','--no-fail-fast','--target-dir',str(campaign/'build'/name)]]
    codes=[]
    log=campaign/'evidence'/(name+'-frozen-selftest.log')
    with log.open('w',encoding='utf-8') as f:
        f.write(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'revision':rev,'dirty':dirty,'source':str(repo)})+'\n');f.flush()
        for command in commands:
            f.write('COMMAND '+json.dumps(command)+'\n');f.flush()
            result=subprocess.run(command,cwd=repo,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=300)
            codes.append(result.returncode);f.write(f'EXIT {result.returncode}\n');f.flush()
    entry={'component':name,'revision':rev,'dirty':bool(dirty),'exit_codes':codes,'finding':'PASS' if all(code==0 for code in codes) else 'FAIL','raw_log':str(log)}
    summary.append(entry);print(json.dumps(entry),flush=True)
(campaign/'evidence/frozen-selftests.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
raise SystemExit(0 if all(e['finding']=='PASS' for e in summary) else 1)
