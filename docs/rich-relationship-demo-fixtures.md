# Rich relationship-demo fixtures

The UI no longer preloads any sample. The `11`–`13` assets are an optional,
three-file fictional batch that developers may select manually to demonstrate
the entity relationship map. They are public static assets only; do not place
real customer, employee, or incident data in this directory.

## Rebuild

From the repository root, with the development Python environment that includes
ReportLab:

```powershell
.venv\Scripts\python.exe scripts\generate-rich-relationship-demo.py
```

The generator is deterministic and writes only these files:

- `apps/web/public/demo-media/11-p0-client-email-thread.pdf`
- `apps/web/public/demo-media/12-developer-slack-thread.pdf`
- `apps/web/public/demo-media/13-calendar-events.txt`

The source contains explicit, human-readable and line-bounded evidence for
`works_at`, `client_of`, `assistant_to`, `assistant_for`, `works_on`, and
`assigned_to`. It does not derive ties from addresses, shared mail domains,
co-mentions, or arbitrary surrounding prose. The PDFs use real mail/signature
and roster formats; the calendar export contains the remaining labelled role
statements. Each generated PDF must remain one A4 page.
