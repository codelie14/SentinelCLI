#!/usr/bin/env python3
"""
Quick test to verify the export command fix
"""

from sentinel import SentinelCLI
import os

def test_export():
    """Test the export command"""
    
    cli = SentinelCLI()
    
    # Run threats analysis first
    print("[*] Running threat analysis...")
    cli._cmd_threats(None)
    
    # Test export command
    print("\n[*] Testing export command...")
    try:
        cli._cmd_export(None)
        print("\n✓ Export command executed successfully!")
        
        # Check if report file was created
        reports_dir = 'reports'
        files = os.listdir(reports_dir)
        md_files = [f for f in files if f.endswith('.md')]
        
        if md_files:
            latest_report = sorted(md_files)[-1]
            filepath = os.path.join(reports_dir, latest_report)
            file_size = os.path.getsize(filepath)
            print(f"✓ Report file created: {latest_report} ({file_size} bytes)")
            return True
        else:
            print("✗ No markdown report file found")
            return False
            
    except Exception as e:
        print(f"✗ Export command failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = test_export()
    exit(0 if success else 1)
