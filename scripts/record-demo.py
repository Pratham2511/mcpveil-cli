#!/usr/bin/env python3
"""Record actual CLI output (asciicast v2). Run inside a disposable sandbox.
Convert using: agg --theme github-dark --font-size 16 --idle-time-limit 2 assets/demo.cast assets/demo.gif
Requires a built checkout. No synthetic terminal output or real credentials.
"""
import codecs, fcntl, json, os, pty, select, struct, subprocess, termios, time
from pathlib import Path
width,height=106,34
out=Path('assets/demo.cast')
commands=[
 ('node dist/cli.js doctor', ['node','dist/cli.js','doctor']),
 ('node dist/cli.js scan --stdio "node test/fixtures/security-cases.mjs echo" --yes',
  ['node','dist/cli.js','scan','--stdio','node test/fixtures/security-cases.mjs echo','--yes']),
 ('node dist/cli.js scan --stdio "node test/fixtures/security-cases.mjs sql-side-effect" --yes',
  ['node','dist/cli.js','scan','--stdio','node test/fixtures/security-cases.mjs sql-side-effect','--yes']),
]
with out.open('w') as cast:
 cast.write(json.dumps({'version':2,'width':width,'height':height,'env':{'TERM':'xterm-256color'},'title':'MCPVeil: real isolated CLI demonstration'})+'\n')
 clock=0.0
 def event(text,delay=0.0):
  global clock
  clock+=delay
  cast.write(json.dumps([round(clock,3),'o',text])+'\n')
 for label,args in commands:
  event('\x1b[2J\x1b[H$ '+label+'\r\n',2.5)
  master,slave=pty.openpty()
  fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',height,width,0,0))
  env={**os.environ,'TERM':'xterm-256color','FORCE_COLOR':'1'};env.pop('NO_COLOR',None)
  proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=slave,stderr=slave,env=env)
  os.close(slave)
  decoder=codecs.getincrementaldecoder("utf8")("replace")
  start=time.monotonic();last=start
  while True:
   if select.select([master],[],[],0.1)[0]:
    try: data=os.read(master,65536)
    except OSError: break
    if not data: break
    now=time.monotonic();event(decoder.decode(data),now-last);last=now
   if time.monotonic()-start>30: proc.kill();raise RuntimeError('Demo exceeded deadline')
  proc.wait();os.close(master)
  if proc.returncode not in (0,1): raise RuntimeError(f'Unexpected demo exit {proc.returncode}')
  event(f'\r\nExit code: {proc.returncode}\r\n',0.2)
  event('',5)
print(f'Recorded actual CLI sessions to {out}')
