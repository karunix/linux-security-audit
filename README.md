## Audit Methodology

This tool performs a lightweight Linux security configuration audit by
inspecting system configuration files and identifying insecure or
high-risk settings.

The audit is **read-only**. No system state is modified.

Each check produces a structured *Finding* consisting of:
    - scope
    - observation
    - severity
    - explanation
    - recommendation
    
    This mirrors the format used in professional security assessments.
    
    ---
    
    ## Architecture Overview
    
    The project is intentionally modular:
        
        - `audit/models.py`  
        Defines the data structures used to represent audit findings and severity
        levels.
        
        - `audit/checks.py`  
        Contains individual security checks. Each check is responsible for:
            - inspecting a specific configuration
            - evaluating risk
            - returning one or more `Finding` objects
            
            - `main.py`  
            Acts as the audit runner. It:
                - executes all registered checks
                - aggregates findings
                - prints a human-readable report
                
                This separation allows new checks to be added without changing core logic.
                
                ---
                
                ## Current Checks
                
                ### SSH Configuration
                - PermitRootLogin
                - SSH protocol version
                - PasswordAuthentication
                
                ### Privilege Escalation
                - Detection of passwordless sudo (`NOPASSWD`) rules in sudoers configuration
                
                ---
                
                ## Severity Levels
                
                Severity reflects *risk impact*, not just misconfiguration presence:
                    
                    - **INFO** – Informational or best-practice guidance
                    - **LOW** – Minor hardening opportunity
                    - **MEDIUM** – Meaningful security risk depending on context
                    - **HIGH** – High-risk configuration that significantly increases attack impact
                    
                    ---
                    
                    ## Running the Audit
                    
                    Create and activate a virtual environment, then run:
                        
                        ```bash
                        python main.py
                        The tool prints a summary of findings directly to the console.
                        
                        Intended Use
                        This project is intended for:
                            
                            learning Python through real-world security tooling
                            
                            practicing Linux security assessment methodology
                            
                            serving as a foundation for more advanced audit features
                            
                            It is not intended to replace full compliance scanners or penetration testing tools.
                            ## Output formats
                            
                            By default, the audit prints a human-readable report:
                                
                                ```bash
                                python main.py
    python main.py --json
    python main.py --json > audit.json
                            
                            
