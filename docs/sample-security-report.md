# CDF AI Security Review

**Input:** `vulnerable-app`
**Gemini model:** `gemini-3.5-flash-lite`
**Loaded / analyzed files:** 12 / 12
**Gemini API calls completed:** 2
**Source coverage:** COMPLETE (within loader limits)
**Findings requiring review:** 4
**Rejected model findings (invalid source evidence):** 1
**Unverified candidates needing citation review:** 1

**Disclaimer:** AI-generated potential weaknesses, not proven vulnerabilities. Source citations were checked; security conclusions and fixes require human validation.

## Executive summary

The reviewer examined 12 of 12 loaded source files and returned 4 source-referenced potential security findings.
Severity counts: CRITICAL: 1, HIGH: 2, MEDIUM: 1, LOW: 0, INFO: 0.
**Overall assessment:** ELEVATED POTENTIAL RISK — prioritize review and remediation of high-impact findings.
This static, AI-assisted review does not establish exploitability or certify the repository as secure.

## Severity summary

- CRITICAL: 1
- HIGH: 2
- MEDIUM: 1
- LOW: 0
- INFO: 0

## Findings

### 1. Service Role Client Bypass of Row Level Security for Profile Retrieval

- **Location:** `supabase/functions/get-profile/index.ts:23`
- **Severity:** MEDIUM (AI-assigned; verify impact and reachability)
- **Confidence:** HIGH
- **CWE:** CWE-284
- **Status:** REVIEW_REQUIRED

**Source evidence and surrounding lines (mechanically extracted)**

```text
  17:       return Response.json(
  18:         { error: "userId is required" },
  19:         { status: 400 }
  20:       );
  21:     }
  22: 
  23:     const supabase = createClient(
  24:       Deno.env.get("SUPABASE_URL") ?? "",
  25:       Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
  26:     );
  27: 
  28:     const { data, error } = await supabase
  29:       .from("profiles")
```

**Why it matters / assumptions / severity rationale**

The get-profile function initializes the Supabase client using the SUPABASE_SERVICE_ROLE_KEY. While profiles might have public read policies, using the service role key bypasses security boundaries entirely and can expose sensitive user information if access control assumptions change.

**Recommended fix**

Use the standard anon/authenticated Supabase client populated with the user's Authorization header so that database-level RLS policies are enforced.

**Example safer code (not compiled or tested)**

```
const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_ANON_KEY") ?? "");
```

### 2. SQL Injection via unsafe query construction

- **Location:** `supabase/functions/search-tasks/index.ts:28`
- **Severity:** CRITICAL (AI-assigned; verify impact and reachability)
- **Confidence:** HIGH
- **CWE:** CWE-89
- **Status:** REVIEW_REQUIRED

**Source evidence and surrounding lines (mechanically extracted)**

```text
  22:       FROM public.tasks
  23:       WHERE title ILIKE '%${searchTerm}%'
  24:       ORDER BY created_at DESC
  25:       LIMIT 25
  26:     `;
  27: 
  28:     const tasks = await sql.unsafe(query);
  29: 
  30:     return Response.json({
  31:       success: true,
  32:       results: tasks,
  33:     });
  34:   } catch (error) {
```

**Why it matters / assumptions / severity rationale**

The search term parameter 'q' from the request URL is directly interpolated into a raw SQL query string using template literals, and then executed via sql.unsafe(). This allows an attacker to inject arbitrary SQL commands, potentially reading or modifying database contents.

**Recommended fix**

Use parameterized queries or the tagged template literal feature provided by the postgres library instead of sql.unsafe() with string interpolation.

**Example safer code (not compiled or tested)**

```
    const tasks = await sql`SELECT id, title, description, status FROM public.tasks WHERE title ILIKE ${'%' + searchTerm + '%'} ORDER BY created_at DESC LIMIT 25`;
```

### 3. Missing Authorization and Ownership Verification on Task Update

- **Location:** `supabase/functions/update-task/index.ts:36`
- **Severity:** HIGH (AI-assigned; verify impact and reachability)
- **Confidence:** HIGH
- **CWE:** CWE-639
- **Status:** REVIEW_REQUIRED

**Source evidence and surrounding lines (mechanically extracted)**

```text
  30: 
  31:     const supabase = createClient(
  32:       Deno.env.get("SUPABASE_URL") ?? "",
  33:       Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
  34:     );
  35: 
  36:     const { data, error } = await supabase
  37:       .from("tasks")
  38:       .update(changes)
  39:       .eq("id", taskId)
  40:       .select()
  41:       .single();
  42: 
```

**Why it matters / assumptions / severity rationale**

The update-task function uses the Supabase service role key to initialize the client, which bypasses all Row Level Security (RLS) policies. It then takes a user-provided taskId and arbitrary changes payload and applies them directly without verifying whether the authenticated user owns or is authorized to update the task.

**Recommended fix**

Authenticate the incoming request to extract the user's JWT, initialize a user-scoped Supabase client instead of the service role key, and enforce proper authorization/ownership checks.

**Example safer code (not compiled or tested)**

```
const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_ANON_KEY") ?? "", { global: { headers: { Authorization: request.headers.get("Authorization")! } } });
```

### 4. Mass Assignment Vulnerability in Edge Function

- **Location:** `supabase/functions/update-task/index.ts:38`
- **Severity:** HIGH (AI-assigned; verify impact and reachability)
- **Confidence:** HIGH
- **CWE:** CWE-915
- **Status:** REVIEW_REQUIRED

**Source evidence and surrounding lines (mechanically extracted)**

```text
  32:       Deno.env.get("SUPABASE_URL") ?? "",
  33:       Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
  34:     );
  35: 
  36:     const { data, error } = await supabase
  37:       .from("tasks")
  38:       .update(changes)
  39:       .eq("id", taskId)
  40:       .select()
  41:       .single();
  42: 
  43:     if (error) {
  44:       throw error;
```

**Why it matters / assumptions / severity rationale**

The update-task Supabase Edge Function directly passes the 'changes' object received from the client request body to the Supabase client update method without filtering or validating allowed fields. This permits clients to modify arbitrary columns on the tasks table, including restricted fields like owner_id or project_id.

**Recommended fix**

Explicitly pick or whitelist allowed fields from the request body before passing them to the database update query.

**Example safer code (not compiled or tested)**

```
    const { title, description, status } = body.changes;
    const { data, error } = await supabase
      .from("tasks")
      .update({ title, description, status })
      .eq("id", taskId)
      .select()
      .single();
```

## Unverified candidates — inspect manually

The following suggestions were NOT accepted as verified findings because 
the model citation did not match exact source evidence. Source excerpts 
below are extracted by Python, not written by Gemini. These are not 
additional confirmed vulnerabilities.

### Cross-Site Scripting (XSS) via dangerouslySetInnerHTML

- **Claimed location:** `src/components/TaskComments.tsx:40`
- **Citation rejection:** evidence does not match the cited source line

**Actual nearby source for manual verification**

```text
  35:           {comments.map((comment) => (
  36:             <div className="comment" key={comment.id}>
  37:               <strong>{comment.author}</strong>
  38: 
  39:               <div
  40:                 dangerouslySetInnerHTML={{
  41:                   __html: comment.text,
  42:                 }}
  43:               />
  44: 
  45:               <small>{comment.createdAt}</small>
```

## Coverage and validation notes

- REJECTED: src/components/TaskComments.tsx:40 (Cross-Site Scripting (XSS) via dangerouslySetInnerHTML): evidence does not match the cited source line

