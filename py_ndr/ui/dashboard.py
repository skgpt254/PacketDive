# ui/dashboard.py
import time
import json
import os
import sys
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

LOG_FILE = "logs/live_events.jsonl"

def make_layout():
    layout = Layout()
    layout.split(Layout(name="header", size=3), Layout(name="main", ratio=1))
    layout["main"].split_row(Layout(name="traffic", ratio=2), Layout(name="alerts", ratio=1))
    return layout

def generate_traffic_table(events):
    table = Table(header_style="bold magenta", expand=True)
    table.add_column("Time", style="dim", width=10)
    table.add_column("Proto", width=12)
    table.add_column("Source", width=16)
    table.add_column("Info")

    for e in events[-20:]: 
        proto = e.get('type', 'UNK')
        color = "white"
        if proto == "DNS": color = "blue"
        elif proto == "HTTPS": color = "green"
        elif proto == "HTTP": color = "yellow"
        elif "ALERT" in proto: color = "bold red"
        
        ts = time.strftime('%H:%M:%S', time.localtime(e.get('timestamp', 0)))
        table.add_row(ts, proto, e.get('src', 'N/A'), str(e.get('info', '')), style=color)
        
    return Panel(table, title="[bold green]Live L7 Traffic Feed[/]", border_style="green")

def generate_alert_panel(alerts):
    content = ""
    for a in alerts[-10:]:
        ts = time.strftime('%H:%M:%S', time.localtime(a.get('timestamp', 0)))
        title_color = "bold magenta" if "AI" in a.get('type') else "bold red"
        content += f"[{ts}] [{title_color}]{a.get('type')}[/]: [bold white]{a.get('src')}[/]\n{a.get('info')}\n---\n"
    return Panel(content, title="[bold red]Heuristic & AI Security Alerts[/]", border_style="red")

def tail_file(filename):
    while not os.path.exists(filename): time.sleep(1)
    with open(filename, "r") as file:
        file.seek(0, os.SEEK_END)
        events, alerts = [], []
        while True:
            line = file.readline()
            if not line:
                yield events, alerts
                time.sleep(0.1)
                continue
            try:
                data = json.loads(line)
                events.append(data)
                if data.get('priority') == "HIGH": alerts.append(data)
                if len(events) > 50: events.pop(0)
                if len(alerts) > 20: alerts.pop(0)
                yield events, alerts
            except: continue

def main():
    if not os.path.exists("logs"): os.makedirs("logs")
    layout = make_layout()
    layout["header"].update(Panel(Text("ENTERPRISE NDR DASHBOARD", justify="center", style="bold white"), style="on blue"))

    with Live(layout, refresh_per_second=4, screen=True):
        for events, alerts in tail_file(LOG_FILE):
            layout["traffic"].update(generate_traffic_table(events))
            layout["alerts"].update(generate_alert_panel(alerts))

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)
