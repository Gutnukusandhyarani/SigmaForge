# Deploy SigmaForge Studio on Render

This is a browser-only guide. The service is read-only and does not collect endpoint events.

1. Commit the updated project package contents to the root of `Gutnukusandhyarani/SigmaForge` on the `main` branch. The key files are `sigmaforge/server.py`, `web/index.html`, `README.md`, and the new `render.yaml`.
2. Sign in to Render with an account permitted to create a service. In the Render dashboard choose **New → Blueprint** and connect the SigmaForge repository.
3. Render reads `render.yaml`. Review the service name, Python runtime, `pip install -r requirements.txt` build command, `python -m sigmaforge serve --host 0.0.0.0 --port $PORT --rules rules --cases tests/cases.json` start command, and `/api/health` health check.
4. Choose the Free plan for this public read-only project if it is offered in your workspace. No persistent storage is required because SigmaForge reads rules and regression cases from its repository.
5. Deploy. In the service's Events/Logs page, verify the deploy succeeds.
6. Copy the public HTTPS URL from the Render service page. Verify `/api/health` returns `{"status":"ok","product":"SigmaForge"}` and the root URL loads the dashboard.

Free Render web services sleep after 15 minutes without inbound traffic and can take about a minute to wake on the next request. This is acceptable for a portfolio proof-of-work dashboard, but not for always-on operational monitoring.

Keep the public repository free of secrets, private detection content and real production log information. The deployed app exposes the repository's rule content and test outcomes to anyone with the URL.
