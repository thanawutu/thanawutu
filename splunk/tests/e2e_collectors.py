import sys
import splunk_e2e as E
for q,lbl in [('index=r7collect sourcetype=rapid7:vm:run | table _time collector status events api_calls error','run summaries'),
          ('index=r7collect | eval bytes=len(_raw), age_h=round((now()-_time)/3600,1) | stats count max(bytes) as max_bytes min(age_h) as min_age_h max(age_h) as max_age_h by sourcetype','events, size and timestamp age per sourcetype'),
          ('index=r7collect sourcetype=rapid7:vm:asset_site | table asset_id hostname site_name credentialed software_count last_scan','asset_site events'),
          ('index=r7collect sourcetype=rapid7:vm:vuln_content | spath path=vuln_id | spath path=cves{} output=cves | eval t=strftime(_time,"%F") | table t vuln_id cves modified','vuln_content: day of _time must equal modified'),
          ('index=_internal sourcetype=splunkd component=ExecProcessor rapid7_ (log_level=ERROR OR log_level=WARN) | table _time log_level message','collector errors in splunkd.log'),
          ('index=_internal sourcetype=splunkd (component=LineBreakingProcessor OR component=DateParserVerbose) r7collect | stats count by component','line-breaking / timestamp warnings')]:
    r=E.run(q,"-1h" if "vuln_content" not in q else "0",label=lbl); E.report(r)
    for x in r["results"][:8]: print("      ", {k:v for k,v in x.items() if not k.startswith('_') or k=='_time'})
