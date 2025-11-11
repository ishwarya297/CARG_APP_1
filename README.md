

1. Install uv in EC2 Linux instance

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
exec bash
uv --version
```

2. Create a python virtual environment ccs using Python v3.9
3. Install all the python modules using requirements.txt
4. make the Bash Script Executable

```bash
cd /root/Projects
uv venv ccs --python 3.12
source ccs/bin/activate
uv pip install -r requirements.txt
chmod +x *.sh
```

5. Start the Azure Scheduler

```bash
bash /root/Projects/start_scheduler.sh
```

6. Stop the Azure Scheduler

```bash
bash /root/Projects/stop_scheduler.sh
```
