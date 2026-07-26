import argparse
from scanner.aws_checks import run_aws_scans
from scanner.reporter import save_json_report, generate_html_report
from rich.console import Console
from rich.table import Table

console = Console()

def main():
    parser = argparse.ArgumentParser(description="CloudProwler - Offensive Cloud Misconfiguration Scanner")
    
    # CLI Arguments
    parser.add_argument("--demo", action="store_true", help="Run scan using mock offline demo data")
    parser.add_argument("--region", type=str, default="us-east-1", help="Target AWS region (default: us-east-1)")
    parser.add_argument("--output", type=str, help="Path to save JSON report file (e.g., report.json)")
    parser.add_argument("--html", type=str, default="reports/report.html", help="Path to save the HTML security dashboard report")
    parser.add_argument("--severity", type=str, choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Filter findings by minimum severity level")
   
    args = parser.parse_args()

    console.print(f"[bold cyan]==[ CloudProwler Security Scanner ]==[/bold cyan]")
    console.print(f"[*] Starting scan (Demo Mode: {args.demo}, Region: {args.region})...\n")
    
    # Run the checks
    all_findings = run_aws_scans(
        demo_mode=args.demo,
        region=args.region
    )
    
    # Apply severity filter if requested
    if args.severity:
        target_severity = args.severity.upper()
        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        target_rank = severity_rank.get(target_severity, 1)
        
        all_findings = [
            f for f in all_findings 
            if severity_rank.get(f.get("severity", "LOW").upper(), 1) >= target_rank
        ]
        console.print(f"[*] Filtered findings to severity >= [bold yellow]{target_severity}[/bold yellow] (Total: {len(all_findings)})")
    if not all_findings:
        console.print("[bold green]✓ No findings detected.[/bold green]")
        return

    # Render a clean Rich terminal table
    table = Table(title="Cloud Security Findings Dashboard", show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Category", style="cyan", width=15)
    table.add_column("Target Resource", style="green", width=25)
    table.add_column("Issue / Vulnerability", style="white")

    for f in all_findings:
        sev = f.get("severity", "MEDIUM").upper()
        sev_styled = f"[red]{sev}[/red]" if sev in ["HIGH", "CRITICAL"] else f"[yellow]{sev}[/yellow]" if sev == "MEDIUM" else f"[blue]{sev}[/blue]"
        
        table.add_row(
            sev_styled,
            f.get("category", "N/A"),
            f.get("resource", "N/A"),
            f.get("description", "N/A")
        )

    console.print(table)
    console.print(f"\n[bold green][*] Scan complete. Total findings displayed: {len(all_findings)}[/bold green]")

    # Export options
    if args.output:
        save_json_report(all_findings, args.output)

    if args.html:
        generate_html_report(all_findings, args.html)

if __name__ == "__main__":
    main()