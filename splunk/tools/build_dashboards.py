#!/usr/bin/env python3
"""Generate the AD Account & Computer Search dashboard in two formats from ONE set of SPL:
  - ../dashboards/ad_account_computer_search.xml          (Simple XML / Classic)
  - ../dashboards/ad_account_computer_search_studio.json  (Dashboard Studio definition JSON)
  - ../dashboards/ad_account_computer_search_studio.xml   (Studio JSON wrapped for import)
All SPL was validated against the target environment (see ../VALIDATION.md, "Validated findings").
"""
import json, os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dashboards")
TITLE = "AD Account & Computer Search"
DESC = ("Search AD user accounts and computers (LDAP via SA-ldapsearch) and correlate with Windows "
        "Security events (Splunk_TA_windows). Click a row to drill down.")

SRC = 'index="$idx$" source="WinEventLog:Security"'
ISO = '"%Y-%m-%dT%H:%M:%S.%6NZ"'            # lastLogonTimestamp / pwdLastSet / lockoutTime (validated)
WHENCREATED = '"%Y-%m-%d %H:%M:%S%:z"'      # whenCreated (validated, different format)
NOT_MACHINE = 'where NOT like(user,"%$$") AND user!="-" AND lower(user)!="anonymous logon"'  # $$ = literal $
SHORT_DEST = 'dest_short=upper(mvindex(split(dest,"."),0))'                                   # dest is FQDN (validated)
SRC_FALLBACK = 'src=coalesce(src,Source_Network_Address,Workstation_Name,"-")'                # src only 81% populated
LT = ('eval LogonType=case(Logon_Type=2,"2 Interactive",Logon_Type=3,"3 Network",Logon_Type=4,"4 Batch",'
      'Logon_Type=5,"5 Service",Logon_Type=7,"7 Unlock",Logon_Type=8,"8 NetworkCleartext",'
      'Logon_Type=9,"9 NewCredentials",Logon_Type=10,"10 RemoteInteractive",Logon_Type=11,"11 CachedInteractive",'
      'isnotnull(Logon_Type),tostring(Logon_Type),true(),"-")')
REASON = ('eval code=lower(coalesce(Sub_Status,Failure_Code,Error_Code,"-")), '
          'Reason=case(EventCode=4624 OR EventCode=4740,"-",'
          'code="0xc000006a" OR code="0x18","Bad password",code="0xc0000064" OR code="0x6","Unknown user",'
          'code="0xc0000234","Locked out",code="0xc0000072" OR code="0x12","Disabled/locked",'
          'code="0xc0000071" OR code="0x17","Password expired",code="0xc0000193","Account expired",'
          'code="0xc0000224","Must change password",code="0xc000006f","Outside logon hours",'
          'code="0xc0000070","Workstation restricted",true(),code)')
OU = 'OU=replace(distinguishedName,"^.*?,(?=(OU|CN|DC)=)","")'
PRIV = ('(?i)^(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Backup Operators|'
        'Server Operators|Print Operators|DnsAdmins|Group Policy Creator Owners|Enterprise Key Admins|Key Admins)$')

# ---------------------------------------------------------------- data sources
# (id, query, base_or_None, time) ; time: "all" = 0..now, "tr" = time picker
DS = {}
def ds(i, q, base=None, time="tr"):
    DS[i] = dict(q=q.strip(), base=base, time=time)

ds("users", f'''
| ldapsearch domain="$domain$"
    search="(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2048))(|(sAMAccountName=$acct$)(cn=$acct$)(displayName=$acct$)(mail=$acct$)(userPrincipalName=$acct$)))"
    attrs="sAMAccountName,cn,objectSid,displayName,userPrincipalName,mail,title,department,manager,userAccountControl,lockoutTime,lastLogonTimestamp,pwdLastSet,whenCreated,memberOf,distinguishedName"
| eval lastLogon_e=strptime(lastLogonTimestamp,{ISO}), pwd_e=strptime(pwdLastSet,{ISO}), lock_e=strptime(lockoutTime,{ISO}), created_e=strptime(whenCreated,{WHENCREATED})
| eval Status=case(isnotnull(mvfind(userAccountControl,"ACCOUNTDISABLE")),"Disabled", lock_e>0,"Locked", true(),"Enabled")
| eval PwdNeverExpires=if(isnotnull(mvfind(userAccountControl,"DONT_EXPIRE_PASSWD")),"Yes","No")
| eval PwdNotRequired=if(isnotnull(mvfind(userAccountControl,"PASSWD_NOTREQD")),"Yes","No")
| eval DaysSinceLogon=if(lastLogon_e>0,round((now()-lastLogon_e)/86400,0),"never")
| eval PwdAgeDays=case(pwd_e>0,round((now()-pwd_e)/86400,0), pwdLastSet="(never)","must change", true(),"-")
| eval Created=strftime(created_e,"%Y-%m-%d"), Manager=replace(mvindex(split(manager,","),0),"^CN=",""), Groups=coalesce(mvcount(memberOf),0), {OU}
''', time="all")

ds("computers", f'''
| ldapsearch domain="$domain$"
    search="(&(objectClass=computer)(|(name=$comp$)(dNSHostName=$comp$)))"
    attrs="name,dNSHostName,operatingSystem,operatingSystemVersion,description,managedBy,userAccountControl,lastLogonTimestamp,whenCreated,distinguishedName"
| eval lastLogon_e=strptime(lastLogonTimestamp,{ISO}), created_e=strptime(whenCreated,{WHENCREATED})
| eval Status=if(isnotnull(mvfind(userAccountControl,"ACCOUNTDISABLE")),"Disabled","Enabled")
| eval Role=case(isnotnull(mvfind(userAccountControl,"SERVER_TRUST_ACCOUNT")),"Domain Controller", isnotnull(mvfind(userAccountControl,"PARTIAL_SECRETS_ACCOUNT")),"RODC", match(operatingSystem,"(?i)server"),"Server", isnull(operatingSystem),"Unknown", true(),"Workstation")
| eval DaysSinceLogon=if(lastLogon_e>0,round((now()-lastLogon_e)/86400,0),"never")
| eval Created=strftime(created_e,"%Y-%m-%d"), ManagedBy=replace(mvindex(split(managedBy,","),0),"^CN=",""), {OU}
| fillnull value="-" operatingSystem operatingSystemVersion ManagedBy
''', time="all")

BS2 = "\\" * 2   # SPL string "\\" = one literal backslash
# Logons 4624/4625 from the accelerated Authentication data model (validated: complete 0.9993, Windows rows
# = raw minus machine accounts). Restricted to WinEventLog because other products also feed the model.
ds("auth", f'''
| tstats summariesonly=true count from datamodel=Authentication
    where nodename=Authentication sourcetype="WinEventLog" (Authentication.signature_id=4624 OR Authentication.signature_id=4625)
      Authentication.user="*$acct$" (Authentication.dest="$comp$" OR Authentication.dest="$comp$.*")
    by _time span=1h Authentication.user Authentication.dest Authentication.src Authentication.action
| rename Authentication.* AS *
| eval user=lower(mvindex(split(mvindex(split(user,"@"),0),"{BS2}"),-1))
| search user="$acct$"
| {NOT_MACHINE} AND user!="unknown"
| eval {SHORT_DEST}, Result=if(action="success","Success","Failure")
| stats sum(count) AS count by _time user dest_short src Result
''')

# Kerberos pre-auth (4771) and NTLM (4776) failures are NOT in the data model (validated) -> raw, aggregated
ds("kerb", f'''
{SRC} (EventCode=4771 OR EventCode=4776) user="$acct$"
| {REASON}
| where EventCode=4771 OR (code!="0x0" AND code!="-")
| {NOT_MACHINE}
| eval user=lower(user), {SRC_FALLBACK}, Protocol=if(EventCode=4771,"Kerberos","NTLM"), DC=upper(mvindex(split(host,"."),0))
| bin _time span=1h
| stats count by _time user src DC Protocol Reason
''')

ds("lockouts", f'''
{SRC} EventCode=4740 user="$acct$"
| eval k=user."|".floor(_time/60)
| stats dc(k) AS count
''')

ds("dc_cov", '''
| ldapsearch domain="$domain$" search="(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" attrs="name,operatingSystem"
| eval host=upper(name)
| join type=left host
    [| tstats count latest(_time) AS last where index="$idx$" source="WinEventLog:Security" earliest=-24h by host
     | eval host=upper(mvindex(split(host,"."),0)) | stats sum(count) AS count max(last) AS last by host]
| eval Status=if(coalesce(count,0)>0,"Logging","NOT LOGGING"), Events24h=coalesce(count,0), LastEvent=if(isnull(last),"-",strftime(last,"%Y-%m-%d %H:%M"))
| table name operatingSystem Status Events24h LastEvent
| sort -Status name
''', time="all")

# KPIs
ds("k_users", "| stats count", "users")
ds("k_dislock", '| where Status!="Enabled" | stats count', "users")
ds("k_notreqd", '| where PwdNotRequired="Yes" AND Status!="Disabled" | stats count', "users")
ds("k_comps", "| stats count", "computers")
ds("k_fail", '| where Result="Failure" | stats sum(count) AS count | fillnull value=0 count', "auth")
ds("k_krb", '| stats sum(count) AS count | fillnull value=0 count', "kerb")
ds("k_lock", '| table count', "lockouts")
ds("k_dcmiss", '| where Status="NOT LOGGING" | stats count', "dc_cov")

# Accounts
ds("t_users", "| table sAMAccountName cn displayName mail title department Manager Status PwdNotRequired PwdNeverExpires DaysSinceLogon PwdAgeDays Groups Created OU objectSid | sort sAMAccountName", "users")
ds("t_groups", f'''| search sAMAccountName="$sel_user$" | fields memberOf | mvexpand memberOf
| eval Group=replace(mvindex(split(memberOf,","),0),"^CN=",""), Privileged=if(match(Group,"{PRIV}"),"YES","-")
| table Group Privileged | sort -Privileged Group''', "users")
ds("t_used", f'''
{SRC} EventCode=4624 user="$sel_user$"
| eval {SHORT_DEST}, {SRC_FALLBACK}
| {LT}
| stats count AS Logons values(LogonType) AS LogonTypes dc(src) AS Sources max(_time) AS Last by dest_short
| eval Last=strftime(Last,"%Y-%m-%d %H:%M") | rename dest_short AS Computer | sort -Logons
''')
ds("c_timeline", '| search user="$sel_user$" | timechart span=1h sum(count) AS count by Result', "auth")
ds("t_changes", f'''
{SRC} EventCode IN (4720,4722,4723,4724,4725,4726,4738,4740,4767,4728,4729,4732,4733,4756,4757)
| eval target=lower(coalesce(user,mvindex(Account_Name,-1))), member_sid=if(mvcount(Security_ID)>=3,mvindex(Security_ID,1),"-")
| where target=lower("$sel_user$") OR target=lower("$sel_cn$") OR member_sid="$sel_sid$"
| eval Action=case(EventCode=4720,"Created",EventCode=4722,"Enabled",EventCode=4723,"Password change",EventCode=4724,"Password reset",EventCode=4725,"Disabled",EventCode=4726,"Deleted",EventCode=4738,"Changed",EventCode=4740,"Locked out",EventCode=4767,"Unlocked",EventCode=4728 OR EventCode=4732 OR EventCode=4756,"Added to group",EventCode=4729 OR EventCode=4733 OR EventCode=4757,"Removed from group")
| eval By=coalesce(src_user,mvindex(Account_Name,0)), Group=coalesce(Group_Name,"-"), Caller=coalesce(Caller_Computer_Name,"-"), DC=upper(mvindex(split(host,"."),0)), Time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table Time Action By Group Caller DC EventCode | sort -Time | head 200
''')

# Computers
ds("t_comps", "| table name dNSHostName Role operatingSystem operatingSystemVersion Status DaysSinceLogon ManagedBy Created OU | sort name", "computers")
ds("c_os", "| stats count by operatingSystem | sort -count", "computers")
ds("t_logged", f'''
{SRC} EventCode IN (4624,4625) (dest="$sel_comp$" OR dest="$sel_comp$.*")
| {NOT_MACHINE}
| eval user=lower(user), {SRC_FALLBACK}
| {LT}
| stats count(eval(EventCode=4624)) AS Success count(eval(EventCode=4625)) AS Failure values(LogonType) AS LogonTypes dc(src) AS Sources max(_time) AS Last by user
| eval Last=strftime(Last,"%Y-%m-%d %H:%M") | sort -Success
''')
ds("t_compchg", f'''
{SRC} EventCode IN (4741,4742,4743) user="$sel_comp$*"
| where upper(replace(user,"[^A-Za-z0-9._-]",""))=upper("$sel_comp$")
| eval Action=case(EventCode=4741,"Created",EventCode=4742,"Changed",EventCode=4743,"Deleted"), By=coalesce(src_user,mvindex(Account_Name,0)), DC=upper(mvindex(split(host,"."),0)), Time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table Time Action By DC EventCode | sort -Time | head 200
''')

# Hygiene & threat
ds("t_stale_u", '| where Status="Enabled" AND (DaysSinceLogon="never" OR tonumber(DaysSinceLogon)>$stale$) | table sAMAccountName displayName department DaysSinceLogon PwdAgeDays PwdNeverExpires OU | sort -DaysSinceLogon', "users")
ds("t_stale_c", '| where Status="Enabled" AND (DaysSinceLogon="never" OR tonumber(DaysSinceLogon)>$stale$) | table name Role operatingSystem DaysSinceLogon OU | sort -DaysSinceLogon', "computers")
ds("t_topfail", '| where Result="Failure" | stats sum(count) AS Failures dc(dest_short) AS Targets dc(src) AS Sources by user | sort -Failures | head 20', "auth")
ds("t_spray", '| where Result="Failure" AND src!="unknown" | stats sum(count) AS Failures dc(user) AS Accounts dc(dest_short) AS Targets by src | where Accounts>=$spray$ | sort -Accounts | head 20', "auth")
ds("t_krbuser", '| stats sum(count) AS Failures dc(src) AS Sources values(Protocol) AS Protocol values(Reason) AS Reasons by user | sort -Failures | head 20', "kerb")
ds("t_krbspray", '| stats sum(count) AS Failures dc(user) AS Accounts values(Protocol) AS Protocol values(Reason) AS Reasons by src | where Accounts>=$spray$ | sort -Accounts | head 20', "kerb")
ds("t_lockcaller", f'''
{SRC} EventCode=4740 user="$acct$"
| eval Caller=upper(coalesce(Caller_Computer_Name,"-")), k=user."|".floor(_time/60)
| stats dc(k) AS Lockouts dc(user) AS Accounts values(user) AS Users max(_time) AS Last by Caller
| eval Users=mvjoin(mvindex(Users,0,4),", "), Last=strftime(Last,"%Y-%m-%d %H:%M") | sort -Lockouts | head 20
''')
ds("t_localgrp", f'''
{SRC} EventCode IN (4732,4733) (host="$comp$" OR host="$comp$.*")
| eval member_sid=if(mvcount(Security_ID)>=3,mvindex(Security_ID,1),mvindex(Security_ID,-1))
| fields _time host EventCode Group_Name src_user Account_Name member_sid
| append [| ldapsearch domain="$domain$" search="(objectClass=domain)" attrs="objectSid" | rename objectSid AS domain_sid | fields domain_sid]
| eventstats values(domain_sid) AS domain_sid
| where isnotnull(EventCode)
| eval Action=if(EventCode=4732,"Added","Removed"), Server=upper(mvindex(split(host,"."),0)), Group=coalesce(Group_Name,"-"),
       By=coalesce(src_user,mvindex(Account_Name,0)), Time=strftime(_time,"%Y-%m-%d %H:%M:%S"),
       MemberType=case(match(member_sid,"^S-1-5-21-") AND replace(member_sid,"-\\d+$$","")=domain_sid,"Domain account",
                       match(member_sid,"^S-1-5-21-"),"Local / other domain", match(member_sid,"^S-1-5-32-"),"Builtin group",
                       match(member_sid,"^S-1-5-"),"Well-known", true(),"Resolved name"),
       Privileged=if(match(Group,"(?i)^(Administrators|Remote Desktop Users|Backup Operators|Remote Management Users|Hyper-V Administrators|Event Log Readers)$$"),"YES","-")
| table Time Server Action Group Privileged MemberType member_sid By
| sort -Time | head 500
''')
ds("t_risky", '| where Status!="Disabled" AND (PwdNotRequired="Yes" OR PwdNeverExpires="Yes") | table sAMAccountName displayName department Status PwdNotRequired PwdNeverExpires PwdAgeDays DaysSinceLogon OU | sort -PwdNotRequired sAMAccountName', "users")

# ---------------------------------------------------------------- inputs
INPUTS = [
    dict(id="acct", type="text", label="Account (sAMAccountName / CN / mail)", default="*"),
    dict(id="comp", type="text", label="Computer (name)", default="*"),
    dict(id="domain", type="text", label="LDAP domain stanza", default="default"),
    dict(id="idx", type="text", label="Windows index", default="wineventlog"),
    dict(id="stale", type="dropdown", label="Stale (days)", default="90", choices=["30", "60", "90", "180"]),
    dict(id="spray", type="dropdown", label="Spray threshold (accounts)", default="10", choices=["5", "10", "20", "50"]),
    dict(id="tr", type="time", label="Event time range", default=("-24h@h", "now")),
]
INPUT_IDS = {i["id"] for i in INPUTS}

# ---------------------------------------------------------------- visualizations
G, A, R = "#53A051", "#F8BE34", "#DC4E41"
COLORS = {
    "Status": {"Enabled": "#1B5E3B", "Disabled": "#4A5058", "Locked": "#8A2A24"},
    "PwdNeverExpires": {"Yes": "#7A5A12"},
    "PwdNotRequired": {"Yes": "#8A2A24"},
    "Privileged": {"YES": "#8A2A24"},
    "Role": {"Domain Controller": "#4B3A8C", "RODC": "#4B3A8C", "Server": "#1D4E79", "Workstation": "#3C444D", "Unknown": "#4A5058"},
    "Action": {"Added to group": "#7A5A12", "Locked out": "#8A2A24", "Deleted": "#8A2A24", "Disabled": "#4A5058",
               "Password reset": "#1D4E79", "Created": "#1B5E3B"},
    "LocalAction": {"Added": "#7A5A12", "Removed": "#1D4E79"},
    "MemberType": {"Domain account": "#1B5E3B", "Local / other domain": "#7A5A12", "Builtin group": "#4B3A8C"},
    "StatusDC": {"Logging": "#1B5E3B", "NOT LOGGING": "#8A2A24"},
}
L, RX, HW, FW = 20, 725, 695, 1400   # left x, right x, half width, full width

V = []   # each: id,type,title,ds,pos,(row),drill,colors,thr
def v(i, typ, title, d, pos, row, drill=None, colors=None, thr=None, md=None, opts=None):
    V.append(dict(id=i, type=typ, title=title, ds=d, pos=pos, row=row, drill=drill or [], colors=colors or {},
                  thr=thr, md=md, opts=opts or {}))

v("md_head", "markdown", None, None, (L, 10, FW, 50), 0,
  md="Validated SPL · LDAP (SA-ldapsearch) + WinEventLog:Security · **click a row** to drill down")
kpis = [("k_users", "Accounts", None), ("k_dislock", "Disabled / Locked", (1, 50)),
        ("k_notreqd", "PASSWD_NOTREQD (enabled)", (1, 1)), ("k_comps", "Computers", None),
        ("k_fail", "Failed logons (4625)", (100, 1000)), ("k_krb", "Kerberos/NTLM failures", (100, 1000)),
        ("k_lock", "Lockouts (4740)", (1, 20)),
        ("k_dcmiss", "DCs NOT logging", (1, 1))]
for n, (d, t, thr) in enumerate(kpis):
    v("viz_" + d, "single", t, d, (L + n * 176, 70, 166, 110), 1, thr=thr)

v("md_acc", "markdown", None, None, (L, 195, FW, 40), 2, md="## Accounts")
v("viz_users", "table", "AD accounts — click a row", "t_users", (L, 240, FW, 340), 3,
  drill=[("sel_user", "sAMAccountName"), ("sel_cn", "cn"), ("sel_sid", "objectSid")],
  colors={"Status": "Status", "PwdNeverExpires": "PwdNeverExpires", "PwdNotRequired": "PwdNotRequired"})
v("viz_groups", "table", "Group membership: $sel_user$", "t_groups", (L, 590, HW, 300), 4, colors={"Privileged": "Privileged"})
v("viz_used", "table", "Computers used by $sel_user$ (click → Computer)", "t_used", (RX, 590, HW, 300), 4,
  drill=[("comp", "Computer"), ("sel_comp", "Computer")])
v("viz_timeline", "column", "Logon timeline: $sel_user$", "c_timeline", (L, 900, HW, 300), 5)
v("viz_changes", "table", "AD changes to $sel_user$", "t_changes", (RX, 900, HW, 300), 5, colors={"Action": "Action"})

v("md_comp", "markdown", None, None, (L, 1215, FW, 40), 6, md="## Computers")
v("viz_comps", "table", "AD computers — click a row", "t_comps", (L, 1260, 1000, 340), 7,
  drill=[("sel_comp", "name")], colors={"Status": "Status", "Role": "Role"})
v("viz_os", "pie", "Computers by operating system", "c_os", (1030, 1260, 390, 340), 7)
v("viz_logged", "table", "Accounts logged on to $sel_comp$ (click → Account)", "t_logged", (L, 1610, HW, 300), 8,
  drill=[("acct", "user"), ("sel_user", "user"), ("sel_cn", "user"), ("sel_sid", "user")])
v("viz_compchg", "table", "Computer account changes: $sel_comp$ (4741–4743)", "t_compchg", (RX, 1610, HW, 300), 8, colors={"Action": "Action"})

v("md_hyg", "markdown", None, None, (L, 1925, FW, 40), 9, md="## Hygiene & threat indicators")
v("viz_stale_u", "table", "Stale enabled accounts (> $stale$ days)", "t_stale_u", (L, 1970, HW, 300), 10)
v("viz_stale_c", "table", "Stale enabled computers (> $stale$ days)", "t_stale_c", (RX, 1970, HW, 300), 10, colors={"Role": "Role"})
v("viz_topfail", "table", "Top failed-logon accounts – 4625 (brute force, T1110.001)", "t_topfail", (L, 2280, HW, 320), 11,
  drill=[("acct", "user"), ("sel_user", "user"), ("sel_cn", "user"), ("sel_sid", "user")])
v("viz_spray", "table", "Password-spray sources – 4625: ≥ $spray$ accounts (T1110.003)", "t_spray", (RX, 2280, HW, 320), 11)
v("viz_krbuser", "table", "Kerberos (4771) / NTLM (4776) failures by account", "t_krbuser", (L, 2610, HW, 320), 12,
  drill=[("acct", "user"), ("sel_user", "user"), ("sel_cn", "user"), ("sel_sid", "user")])
v("viz_krbspray", "table", "Kerberos / NTLM spray sources: ≥ $spray$ accounts (T1110.003)", "t_krbspray", (RX, 2610, HW, 320), 12)
v("viz_lockcaller", "table", "Lockout sources (4740 Caller_Computer_Name)", "t_lockcaller", (L, 2940, HW, 300), 13)
v("viz_dccov", "table", "Domain controller log coverage (last 24h)", "dc_cov", (RX, 2940, HW, 300), 13, colors={"Status": "StatusDC"})
v("viz_risky", "table", "Risky enabled accounts: PASSWD_NOTREQD / password never expires", "t_risky", (L, 3250, FW, 320), 14,
  colors={"Status": "Status", "PwdNotRequired": "PwdNotRequired", "PwdNeverExpires": "PwdNeverExpires"})
v("viz_localgrp", "table", "Local group changes on servers (4732/4733 · T1098)", "t_localgrp", (L, 3580, FW, 340), 15,
  colors={"Action": "LocalAction", "Privileged": "Privileged", "MemberType": "MemberType"})
HEIGHT = 3940
DEPENDS = {"viz_groups": "sel_user", "viz_used": "sel_user", "viz_timeline": "sel_user", "viz_changes": "sel_user",
           "viz_logged": "sel_comp", "viz_compchg": "sel_comp"}

# ================================================================= Dashboard Studio JSON
def studio():
    d = {"title": TITLE, "description": DESC, "inputs": {}, "dataSources": {}, "visualizations": {},
         "defaults": {"dataSources": {"ds.search": {"options": {"queryParameters": {
             "earliest": "$tr.earliest$", "latest": "$tr.latest$"}}}}},
         "layout": {"type": "absolute",
                    "options": {"width": 1440, "height": HEIGHT, "display": "auto-scale", "backgroundColor": "#111418"},
                    "structure": [], "globalInputs": []}}
    for i in INPUTS:
        key = "input_" + i["id"]
        if i["type"] == "text":
            d["inputs"][key] = {"type": "input.text", "title": i["label"],
                                "options": {"token": i["id"], "defaultValue": i["default"]}}
        elif i["type"] == "dropdown":
            d["inputs"][key] = {"type": "input.dropdown", "title": i["label"],
                                "options": {"token": i["id"], "defaultValue": i["default"],
                                            "items": [{"label": c, "value": c} for c in i["choices"]]}}
        else:
            d["inputs"][key] = {"type": "input.timerange", "title": i["label"],
                                "options": {"token": i["id"], "defaultValue": ",".join(i["default"])}}
        d["layout"]["globalInputs"].append(key)
    for k, s in DS.items():
        if s["base"]:
            d["dataSources"]["ds_" + k] = {"type": "ds.chain", "name": k,
                                           "options": {"extend": "ds_" + s["base"], "query": s["q"]}}
        else:
            o = {"query": s["q"]}
            if s["time"] == "all":
                o["queryParameters"] = {"earliest": "0", "latest": "now"}
            d["dataSources"]["ds_" + k] = {"type": "ds.search", "name": k, "options": o}
    for x in V:
        viz = {}
        if x["type"] == "markdown":
            viz = {"type": "splunk.markdown", "options": {"markdown": x["md"], "fontColor": "#C5CCD3"}}
        else:
            viz = {"type": {"single": "splunk.singlevalue", "table": "splunk.table", "column": "splunk.column",
                            "pie": "splunk.pie"}[x["type"]],
                   "title": x["title"], "dataSources": {"primary": "ds_" + x["ds"]}, "options": dict(x["opts"])}
            if x["type"] == "single" and x["thr"]:
                t1, t2 = x["thr"]
                cfg = [{"to": t1, "value": G}] + ([{"from": t1, "to": t2, "value": A}] if t2 > t1 else []) + \
                      [{"from": t2, "value": R}]
                viz["options"]["backgroundColor"] = "> majorValue | rangeValue(bgCfg)"
                viz["options"]["majorColor"] = "#FFFFFF"
                viz["context"] = {"bgCfg": cfg}
            if x["type"] == "column":
                viz["options"].update({"stackMode": "stacked", "legendDisplay": "top",
                                       "seriesColorsByField": {"Success": "#4EA1F3", "Failure": "#F28B3C", "Lockout": "#F5D76E"}})
            if x["type"] == "table" and x["colors"]:
                viz["options"]["columnFormat"] = {}
                viz.setdefault("context", {})
                for col, pal in x["colors"].items():
                    ck = "c_" + col + "_" + pal
                    viz["options"]["columnFormat"][col] = {
                        "data": f'> table | seriesByName("{col}")',
                        "rowBackgroundColors": f'> table | seriesByName("{col}") | matchValue({ck})'}
                    viz["context"][ck] = [{"match": m, "value": c} for m, c in COLORS[pal].items()]
            if x["drill"]:
                viz["eventHandlers"] = [{"type": "drilldown.setToken", "options": {
                    "tokens": [{"token": t, "key": f"row.{f}.value"} for t, f in x["drill"]]}}]
        d["visualizations"][x["id"]] = viz
        px, py, pw, ph = x["pos"]
        d["layout"]["structure"].append({"item": x["id"], "type": "block",
                                         "position": {"x": px, "y": py, "w": pw, "h": ph}})
    return d

# ================================================================= Simple XML
def esc(s): return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def simplexml():
    o = [f'<form version="1.1" theme="dark">', f"  <label>{esc(TITLE)}</label>", f"  <description>{esc(DESC)}</description>",
         '  <fieldset submitButton="true" autoRun="true">']
    for i in INPUTS:
        if i["type"] == "text":
            o += [f'    <input type="text" token="{i["id"]}"><label>{esc(i["label"])}</label><default>{i["default"]}</default></input>']
        elif i["type"] == "dropdown":
            ch = "".join(f'<choice value="{c}">{c}</choice>' for c in i["choices"])
            o += [f'    <input type="dropdown" token="{i["id"]}"><label>{esc(i["label"])}</label>{ch}<default>{i["default"]}</default></input>']
        else:
            o += [f'    <input type="time" token="{i["id"]}"><label>{esc(i["label"])}</label>'
                  f'<default><earliest>{i["default"][0]}</earliest><latest>{i["default"][1]}</latest></default></input>']
    o += ["  </fieldset>", ""]
    def times(s):
        return ("<earliest>0</earliest><latest>now</latest>" if s["time"] == "all"
                else "<earliest>$tr.earliest$</earliest><latest>$tr.latest$</latest>")
    for k, s in DS.items():           # global base searches
        if not s["base"] and k in ("users", "computers", "auth", "kerb", "lockouts", "dc_cov"):
            o += [f'  <search id="base_{k}">', f"    <query><![CDATA[{s['q']}]]></query>", f"    {times(s)}", "  </search>"]
    def search_el(dk):
        s = DS[dk]
        if s["base"]:
            return f'<search base="base_{s["base"]}"><query><![CDATA[{s["q"]}]]></query></search>'
        if dk in ("users", "computers", "auth", "kerb", "lockouts", "dc_cov"):
            return f'<search base="base_{dk}"><query>| table *</query></search>'
        return f'<search><query><![CDATA[{s["q"]}]]></query>{times(s)}</search>'
    rows = {}
    for x in V:
        rows.setdefault(x["row"], []).append(x)
    for r in sorted(rows):
        items = rows[r]
        dep = {DEPENDS.get(x["id"]) for x in items} - {None}
        o.append(f'  <row depends="${"$,$".join(sorted(dep))}$">' if dep else "  <row>")
        for x in items:
            o.append("    <panel>")
            if x["type"] == "markdown":
                txt = x["md"].replace("## ", "").replace("**", "")
                o.append(f'      <html><h2 style="margin:4px 0;color:#C5CCD3">{esc(txt)}</h2></html>')
            elif x["type"] == "single":
                o += [f"      <single><title>{esc(x['title'])}</title>", f"        {search_el(x['ds'])}",
                      '        <option name="drilldown">none</option>']
                if x["thr"]:
                    t1, t2 = x["thr"]
                    rv, rc = ([t1 - 1, t2 - 1], [G, A, R]) if t2 > t1 else ([t1 - 1], [G, R])
                    o += ['        <option name="colorMode">block</option>', '        <option name="useColors">1</option>',
                          f'        <option name="rangeValues">{json.dumps(rv)}</option>',
                          f'        <option name="rangeColors">{json.dumps([c.replace("#", "0x") for c in rc])}</option>']
                o.append("      </single>")
            elif x["type"] in ("column", "pie"):
                o += [f"      <chart><title>{esc(x['title'])}</title>", f"        {search_el(x['ds'])}",
                      f'        <option name="charting.chart">{x["type"]}</option>']
                if x["type"] == "column":
                    o += ['        <option name="charting.chart.stackMode">stacked</option>',
                          '        <option name="charting.fieldColors">{"Success":0x4EA1F3,"Failure":0xF28B3C,"Lockout":0xF5D76E}</option>']
                o.append("      </chart>")
            else:
                o += [f"      <table><title>{esc(x['title'])}</title>", f"        {search_el(x['ds'])}",
                      '        <option name="count">10</option>',
                      f'        <option name="drilldown">{"row" if x["drill"] else "none"}</option>']
                for col, pal in x["colors"].items():
                    m = ",".join(f'"{k}":{c}' for k, c in COLORS[pal].items())
                    o.append(f'        <format type="color" field="{col}"><colorPalette type="map">{{{m}}}</colorPalette></format>')
                if x["drill"]:
                    o.append("        <drilldown>")
                    for t, f in x["drill"]:
                        if t in INPUT_IDS:
                            o.append(f'          <set token="form.{t}">$row.{f}$</set>')
                        o.append(f'          <set token="{t}">$row.{f}$</set>')
                    o.append("        </drilldown>")
                o.append("      </table>")
            o.append("    </panel>")
        o.append("  </row>")
    o.append("</form>")
    return "\n".join(o) + "\n"

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    sj = studio()
    js = json.dumps(sj, indent=2, ensure_ascii=False)
    open(os.path.join(OUT, "ad_account_computer_search_studio.json"), "w").write(js + "\n")
    open(os.path.join(OUT, "ad_account_computer_search_studio.xml"), "w").write(
        f'<dashboard version="2" theme="dark">\n  <label>{esc(TITLE)}</label>\n  <description>{esc(DESC)}</description>\n'
        f'  <definition><![CDATA[\n{js}\n]]></definition>\n  <meta type="hiddenElements"><![CDATA[{{"hideEdit":false,"hideOpenInSearch":false,"hideExport":false}}]]></meta>\n</dashboard>\n')
    open(os.path.join(OUT, "ad_account_computer_search.xml"), "w").write(simplexml())
    print("datasources:", len(DS), "visualizations:", len(V))
