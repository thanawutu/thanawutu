import sys, splunk_e2e as E
q=sys.argv[5]; e=sys.argv[6] if len(sys.argv)>6 else "-24h"
r=E.run(q,e,label=q[:100]); E.report(r)
for x in r["results"][:30]: print("      ", {k:v for k,v in x.items() if not k.startswith('_') or k=='_time'})
