import tempfile
import subprocess

def install_polkit_rule(self):
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
    
    # The rule file needs to be installed with sudo
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
        tmp_file.write(rule_content)
        tmp_file.flush()
        
        result = subprocess.run(
            ['sudo', 'cp', tmp_file.name, '/etc/polkit-1/rules.d/90-gvm-service-management.rules'],
            capture_output=True,
            text=True,
            check=False
        )
        
        os.unlink(tmp_file.name)
        
        if result.returncode == 0:
            subprocess.run(
                ['sudo', 'chmod', '644', '/etc/polkit-1/rules.d/90-gvm-service-management.rules'],
                capture_output=True,
                text=True
            )
            return True
        else:
            return False