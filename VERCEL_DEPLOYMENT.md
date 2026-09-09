# Vercel deployment

- Framework Preset: Other
- Root Directory: ./
- Build Command: leave empty
- Output Directory: leave empty
- Install Command: pip install -r requirements.txt
- Environment Variables: none required

The Flask entry point is `api/index.py` and `vercel.json` routes incoming paths to it.

Important limitation: Vercel serverless functions have request/execution limits. For large PCAP files or long Scapy analyses, use a dedicated Python backend instead.
