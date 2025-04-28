import os
import sys
import tempfile
import subprocess

def install_polkit_rule():
    """Install the polkit rule to allow managing GVM service"""
    rule_content = """polkit.addRule(function(action, subject) {
                        // Allow managing the gvmd service specifically
                        if (action.id == "org.freedesktop.systemd1.manage-units" &&
                            action.lookup("unit") == "gvmd.service") {
                            
                            // Allow any local user to manage this service
                            // In production, you may want to restrict this further
                            if (subject.local) {
                                return polkit.Result.YES;
                            }
                        }
                    });
                    """
    
    # Create a temporary file to write the rule
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
        tmp_file.write(rule_content)
        tmp_file.flush()
        
        # Copy the rule file to the proper system location
        result = subprocess.run(
            ['sudo', 'cp', tmp_file.name, '/etc/polkit-1/rules.d/90-gvm-service-management.rules'],
            capture_output=True,
            text=True
        )
        
        os.unlink(tmp_file.name)  # Clean up temp file
        
        if result.returncode == 0:
            subprocess.run(
                ['sudo', 'chmod', '644', '/etc/polkit-1/rules.d/90-gvm-service-management.rules'],
                capture_output=True,
                text=True
            )
            print("Polkit rule installed successfully.")
            return True
        else:
            print("Failed to install polkit rule:")
            print(result.stderr)
            return False

if __name__ == "__main__":
    success = install_polkit_rule()
    if not success:
        sys.exit(1)