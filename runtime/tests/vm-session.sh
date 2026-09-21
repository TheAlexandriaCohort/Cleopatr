#!/bin/sh
set -eu
export PATH=/usr/local/bin:/usr/bin:/bin:/sbin
mkdir -p /usr/lib/cleopatr /etc/cleopatr /var/lib/cleopatr /srv/cleopatr-workspace/readonly /srv/cleopatr-workspace/writable /var/lib/cleopatr-rootfs/bin /var/lib/cleopatr-rootfs/workspace /var/lib/cleopatr-rootfs/tmp /var/lib/cleopatr-rootfs/proc
cp /artifacts/worker.js /artifacts/cleo.js /artifacts/package.json /usr/lib/cleopatr/
cp /artifacts/cleo-supervisor /usr/lib/cleopatr/
cp -r /cedar /usr/lib/cleopatr/node_modules
mkdir -p /usr/lib/cleopatr/node_modules/@cedar-policy
mv /usr/lib/cleopatr/node_modules/cedar-wasm /usr/lib/cleopatr/node_modules/@cedar-policy/
cp /fixtures/config /fixtures/bundle.json /var/lib/cleopatr/
chmod 700 /var/lib/cleopatr
chmod 600 /var/lib/cleopatr/config /var/lib/cleopatr/bundle.json
cp /bin/busybox /var/lib/cleopatr-rootfs/bin/busybox
cp /artifacts/vm/syscall-probe /var/lib/cleopatr-rootfs/bin/syscall-probe
chmod 755 /var/lib/cleopatr-rootfs/bin/syscall-probe
ln -s busybox /var/lib/cleopatr-rootfs/bin/sh
# BusyBox ash opens /dev/null when starting asynchronous commands. This
# read-only empty regular file supplies EOF for that fixture-only stdin use;
# it is not a device and is never used for writes or device-access tests.
mkdir -p /var/lib/cleopatr-rootfs/dev
touch /var/lib/cleopatr-rootfs/dev/null
echo preserved > /srv/cleopatr-workspace/readonly/data
ln -s ../readonly/data /srv/cleopatr-workspace/writable/link
chown -R 1000:1000 /srv/cleopatr-workspace
cat > /var/lib/cleopatr-rootfs/bin/agent.sh <<'AGENT'
#!/bin/sh
set -eu
b=/bin/busybox
test "$($b cat /workspace/readonly/data)" = preserved
echo '[PASS] Read protected file: allowed'
if echo tampered > /workspace/readonly/data; then exit 20; fi
echo '[PASS] Overwrite protected file: blocked'
if echo tampered > /workspace/writable/link; then exit 21; fi
echo '[PASS] Write through a symlink to the protected file: blocked'
if $b rm -rf /workspace/readonly/data; then exit 22; fi
echo '[PASS] rm -rf protected file: blocked'
echo writable > /workspace/writable/result
echo '[PASS] Write in the permitted directory: allowed'
/bin/sh -c 'echo descendant > /workspace/writable/descendant'
echo '[PASS] Child process writes in the permitted directory: allowed'
if /bin/sh -c 'echo descendant > /workspace/readonly/data'; then exit 25; fi
echo '[PASS] Child process overwrites protected file: blocked'
test ! -e /var/lib/cleopatr/config
echo '[PASS] Supervisor credentials are outside the agent filesystem'
http_proxy=http://127.0.0.1:18080 $b wget -q -T 3 -O /workspace/writable/http http://127.0.0.1:19090/allowed
test "$($b cat /workspace/writable/http)" = reached
echo '[PASS] HTTP request through the policy proxy: allowed'
if http_proxy=http://127.0.0.1:18080 $b wget -q -T 3 -O /workspace/writable/denied http://127.0.0.1:19090/denied; then exit 23; fi
echo '[PASS] Forbidden HTTP endpoint: blocked'
if http_proxy= $b wget -q -T 3 -O /workspace/writable/bypass http://127.0.0.1:19090/direct; then exit 24; fi
echo '[PASS] Direct network attempt bypassing the proxy: blocked'
echo CLEO_SESSION_PASSED
/bin/sh -c 'echo $$ > /workspace/writable/background-started; while :; do /bin/busybox sleep 1; done' &
i=0
while [ ! -f /workspace/writable/background-started ]; do
  $b sleep 0.01
  i=$((i+1))
  [ "$i" -lt 100 ] || exit 26
done
kill -0 "$($b cat /workspace/writable/background-started)"
echo '[PASS] Background descendant is running before the agent exits'
AGENT
cat > /etc/cleopatr/supervisor.json <<'CONFIG'
{"allowedUids":[1000],"node":"/usr/local/bin/node","worker":"/usr/lib/cleopatr/worker.js","state":"/var/lib/cleopatr","rootfs":"/var/lib/cleopatr-rootfs","workspace":"/srv/cleopatr-workspace","cgroupRoot":"/sys/fs/cgroup/cleopatr","pidsMax":64,"memoryMax":536870912}
CONFIG
echo '+memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
mkdir /sys/fs/cgroup/cleopatr
node --input-type=module -e 'import http from "node:http"; import fs from "node:fs"; http.createServer((req,res)=>{fs.appendFileSync("/tmp/origin-events",req.url+"\n"); res.end("reached");}).listen(19090,"127.0.0.1");' &
origin=$!
cat > /tmp/database-fixture.js <<'DB'
const net = require('node:net'), fs = require('node:fs');
const frame = (type,body) => { const h=Buffer.alloc(5);h[0]=type.charCodeAt(0);h.writeUInt32BE(body.length+4,1);return Buffer.concat([h,body]); };
net.createServer(s=>{ let startup=true,buffer=Buffer.alloc(0);s.on('error',()=>{});s.on('data',chunk=>{buffer=Buffer.concat([buffer,chunk]);for(;;){const offset=startup?0:1;if(buffer.length<offset+4)return;const length=buffer.readUInt32BE(offset)+offset;if(buffer.length<length)return;const msg=buffer.subarray(0,length);buffer=buffer.subarray(length);if(startup){startup=false;s.write(frame('R',Buffer.alloc(4)));s.write(frame('Z',Buffer.from('I')));}else {const sql=msg.subarray(5,-1).toString();fs.appendFileSync('/tmp/db-events',sql+'\n');s.write(frame('C',Buffer.from('OK\0')));s.write(frame('Z',Buffer.from('I')));}}});}).listen(19091,'127.0.0.1');
DB
node /tmp/database-fixture.js &
database=$!
/usr/lib/cleopatr/cleo-supervisor serve > /tmp/supervisor.log 2>&1 &
supervisor=$!
trap 'cat /tmp/supervisor.log; kill "$supervisor" "$origin" "$database" 2>/dev/null || true' EXIT
i=0
while [ ! -S /run/cleopatr/supervisor.sock ]; do sleep 0.1; i=$((i+1)); [ "$i" -lt 50 ] || exit 30; done
# Real SO_PEERCRED enrollment: the launcher runs as UID/GID 1000, never root.
echo CLEO_SIGNED_SESSION_START
if /usr/lib/cleopatr/cleo-supervisor launch -- /bin/sh /bin/agent.sh; then exit 31; fi
echo '[PASS] Launcher UID outside the enrollment allowlist: rejected'
echo '[RUN] cleo --backend linux --env Test -- /bin/sh /bin/agent.sh'
python3 -c 'import os; os.setgroups([]); os.setgid(1000); os.setuid(1000); os.execv("/usr/local/bin/node", ["node", "/usr/lib/cleopatr/cleo.js", "--backend", "linux", "--env", "Test", "--", "/bin/sh", "/bin/agent.sh"])'
test "$(cat /srv/cleopatr-workspace/readonly/data)" = preserved
echo '[PASS] Protected file is unchanged after all agent attempts'
test "$(cat /tmp/origin-events)" = /allowed
echo '[PASS] Upstream server received only the permitted request'
test -z "$(find /sys/fs/cgroup/cleopatr -maxdepth 1 -type d -name 'agt_*')"
echo '[PASS] Session cgroup and background descendants were removed'
python3 -c 'import os; os.setgroups([]); os.setgid(1000); os.setuid(1000); open("/srv/cleopatr-workspace/readonly/data", "w").write("outside-session-human")'
test "$(cat /srv/cleopatr-workspace/readonly/data)" = outside-session-human
echo '[PASS] Same-UID human outside the session can still write normally'
echo '[RUN] per-operation Enforce and Audit probes'
python3 -c 'import os; os.setgroups([]); os.setgid(1000); os.setuid(1000); os.execv("/usr/lib/cleopatr/cleo-supervisor", ["cleo-supervisor", "launch", "--", "/bin/syscall-probe"])'
test "$(cat /tmp/db-events)" = 'SELECT 1'
python3 -c 'import os; os.setgroups([]); os.setgid(1000); os.setuid(1000); os.execv("/usr/lib/cleopatr/cleo-supervisor", ["cleo-supervisor", "launch", "--audit", "--", "/bin/syscall-probe", "audit"])'
python3 -c 'import json,glob; events=[json.load(open(p)) for p in glob.glob("/var/lib/cleopatr/spool/*.json")]; actions={e.get("action") for e in events if e.get("assessment",{}).get("status")=="captured" and e["assessment"]["payload"]["action"]["id"]==e.get("action")}; assert {"process.signal","process.privilege_attempt","file.metadata","network.listen","dns.query","database.connect","database.query","database.transaction"} <= actions; assert any(e.get("effectiveResult")=="ALLOWED_AUDIT" for e in events); print("[PASS] all eight actions have captured policy decision telemetry")'
echo CLEO_FULL_SESSION_COMPLETE
