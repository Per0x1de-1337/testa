from mcp.server.fastmcp import FastMCP

from kubernetes import client, config
from typing import Optional, List, Dict, Any

mcp = FastMCP("Knative Tools MCP")

def load_kube_config(context: Optional[str] = None):
    """Load kubeconfig for a given context."""
    config.load_kube_config(context=context)

@mcp.tool()
async def list_pods(namespace: str = "default", label_selector: Optional[str] = None,
              field_selector: Optional[str] = None, context: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List pods in a namespace.
    Returns a list of pod dictionaries.
    """
    load_kube_config(context)
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace=namespace, label_selector=label_selector, field_selector=field_selector)
    return [pod.to_dict() for pod in pods.items]

@mcp.tool()
async def get_nodes(context: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Get nodes in the cluster.
    Returns a list of node dictionaries.
    """
    load_kube_config(context)
    v1 = client.CoreV1Api()
    nodes = v1.list_node()
    return [node.to_dict() for node in nodes.items]

@mcp.tool()
async def create_pod(
    namespace: str,
    pod_name: str,
    image: str,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a pod in a specified namespace.
    Returns the created pod's dictionary.
    """
    load_kube_config(context)
    v1 = client.CoreV1Api()
    
    pod_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name},
        "spec": {
            "containers": [{"name": pod_name, "image": image}]
        }
    }
    pod = v1.create_namespaced_pod(namespace=namespace, body=pod_manifest)
    return pod.to_dict()

@mcp.tool()
async def delete_pod(
    namespace: str,
    pod_name: str,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Delete a pod in a specified namespace.
    Returns the status of the deletion.
    """
    load_kube_config(context)
    v1 = client.CoreV1Api()
    
    response = v1.delete_namespaced_pod(name=pod_name, namespace=namespace)
    return response.to_dict()
@mcp.tool()
async def get_pod_logs(
    namespace: str,
    pod_name: str,
    context: Optional[str] = None
) -> str:
    """
    Get logs from a specified pod in a namespace.
    Returns the logs as a string.
    """
    load_kube_config(context)
    v1 = client.CoreV1Api()
    
    logs = v1.read_namespaced_pod_log(name=pod_name, namespace=namespace)
    return logs
@mcp.tool()
async def get_pod_status(
    namespace: str,
    pod_name: str,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get the status of a specified pod in a namespace.
    Returns the pod's status as a dictionary.
    """
    load_kube_config(context)
    v1 = client.CoreV1Api()
    
    pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
    return pod.status.to_dict() 
@mcp.tool()
async def describe_pod(
    namespace: str,
    pod_name: str,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Describe a specified pod in a namespace.
    Returns the pod's description as a dictionary.
    """
    load_kube_config(context)
    v1 = client.CoreV1Api()
    
    pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
    return pod.to_dict()
@mcp.tool()
async def create_deployment(
    namespace: str,
    deployment_name: str,
    image: str,
    replicas: int = 1,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a deployment in a specified namespace.
    Returns the created deployment's dictionary.
    """
    load_kube_config(context)
    apps_v1 = client.AppsV1Api()
    
    deployment_manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": deployment_name},
        "spec": {
            "replicas": replicas,
            "selector": {
                "matchLabels": {"app": deployment_name}
            },
            "template": {
                "metadata": {"labels": {"app": deployment_name}},
                "spec": {
                    "containers": [{"name": deployment_name, "image": image}]
                }
            }
        }
    }
    
    deployment = apps_v1.create_namespaced_deployment(namespace=namespace, body=deployment_manifest)
    return deployment.to_dict()
@mcp.tool()
async def delete_deployment(
    namespace: str,
    deployment_name: str,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Delete a deployment in a specified namespace.
    Returns the status of the deletion.
    """
    load_kube_config(context)
    apps_v1 = client.AppsV1Api()
    
    response = apps_v1.delete_namespaced_deployment(name=deployment_name, namespace=namespace)
    return response.to_dict()
@mcp.tool()
async def get_deployment_status(
    namespace: str,
    deployment_name: str,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get the status of a specified deployment in a namespace.
    Returns the deployment's status as a dictionary.
    """
    load_kube_config(context)
    apps_v1 = client.AppsV1Api()
    
    deployment = apps_v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)
    return deployment.status.to_dict()
@mcp.tool()
async def list_deployments(
    namespace: str = "default",
    context: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    List deployments in a specified namespace.
    Returns a list of deployment dictionaries.
    """
    load_kube_config(context)
    apps_v1 = client.AppsV1Api()
    
    deployments = apps_v1.list_namespaced_deployment(namespace=namespace)
    return [deployment.to_dict() for deployment in deployments.items]

@mcp.tool()
async def get_deployment_logs(
    namespace: str,
    deployment_name: str,
    context: Optional[str] = None
) -> str:
    """
    Get logs from a specified deployment in a namespace.
    Returns the logs as a string.
    """
    load_kube_config(context)
    apps_v1 = client.AppsV1Api()
    
    logs = apps_v1.read_namespaced_deployment_log(name=deployment_name, namespace=namespace)
    return logs
@mcp.tool()
async def describe_deployment(
    namespace: str,
    deployment_name: str,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Describe a specified deployment in a namespace.
    Returns the deployment's description as a dictionary.
    """
    load_kube_config(context)
    apps_v1 = client.AppsV1Api()
    
    deployment = apps_v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)
    return deployment.to_dict()
@mcp.tool()
async def scale_deployment(
    namespace: str,
    deployment_name: str,
    replicas: int,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Scale a deployment in a specified namespace.
    Returns the scaled deployment's dictionary.
    """
    load_kube_config(context)
    apps_v1 = client.AppsV1Api()
    
    scale = client.V1Scale(
        spec=client.V1ScaleSpec(replicas=replicas)
    )
    
    response = apps_v1.patch_namespaced_deployment_scale(
        name=deployment_name,
        namespace=namespace,
        body=scale
    )
    
    return response.to_dict()
@mcp.tool()
async def list_services(
    namespace: str = "default",
    context: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    List services in a specified namespace.
    Returns a list of service dictionaries.
    """
    load_kube_config(context)
    v1 = client.CoreV1Api()
    
    services = v1.list_namespaced_service(namespace=namespace)
    return [service.to_dict() for service in services.items]
@mcp.tool()
async def create_service(
    namespace: str,
    service_name: str,
    ports: List[Dict[str, Any]],
    selector: Dict[str, str],
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a service in a specified namespace.
    Returns the created service's dictionary.
    """
    load_kube_config(context)
    v1 = client.CoreV1Api()
    
    service_manifest = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": service_name},
        "spec": {
            "ports": ports,
            "selector": selector,
            "type": "ClusterIP"
        }
    }
    
    service = v1.create_namespaced_service(namespace=namespace, body=service_manifest)
    return service.to_dict()


# ////////////////////////////////////////////////////////////
# Binding policies

def load_kube_config(context=None):
    try:
        print(f"Loading kube config for context: {context}")
        config.load_kube_config(context=context)
        c = client.Configuration.get_default_copy()
        c.verify_ssl = False
        c.ssl_ca_cert = None  # Explicitly disable SSL verification
        client.Configuration.set_default(c)
        
        # Print current context
        current_context = config.list_kube_config_contexts()[1]
        print(f"Current context: {current_context['name']}")
        
        return current_context
    except Exception as e:
        print(f"Error loading kube config: {str(e)}")
        raise

def is_kubernetes_builtin_resource(resource: str) -> bool:
    # Implement this based on your resource knowledge or a lookup table.
    builtins = {"pods", "deployments", "services", "namespaces", "configmaps", "secrets"}
    return resource in builtins

def get_api_group_for_crd(resource: str, crd_api_groups: Dict[str, str]) -> str:
    return crd_api_groups.get(resource, "")

def format_labels(labels: Dict[str, str]) -> List[str]:
    return [f"{k}: {v}" for k, v in labels.items()]

def create_binding_policy_helper(
    policy_name: str,
    namespace: str,
    cluster_labels: Dict[str, str],
    workload_labels: Dict[str, str],
    resource_configs: List[Dict[str, Any]],
    crd_api_groups: Dict[str, str],
    namespaces_to_sync: Optional[List[str]] = None,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a KubeStellar BindingPolicy CRD in the target cluster.
    """
    try:
        load_kube_config(context)
        api = client.CustomObjectsApi()

        # First check if the API group exists
        try:
            api.list_cluster_custom_object(
                group="control.kubestellar.io",
                version="v1alpha1",
                plural="bindingpolicies"
            )
        except client.exceptions.ApiException as e:
            if e.status == 404:
                try:
                    # Try with v1alpha2 version as well
                    api.list_cluster_custom_object(
                        group="control.kubestellar.io",
                        version="v1alpha2",
                        plural="bindingpolicies"
                    )
                    print("Using v1alpha2 API version")
                except client.exceptions.ApiException as e2:
                    if e2.status == 404:
                        return {
                            "error": "BindingPolicy API not accessible",
                            "message": "The BindingPolicy API endpoint is not accessible. Please verify the API version and permissions."
                        }
                    raise e2
            raise e

        # Build downsync rules
        downsync_rules = []

        # Handle CRDs first
        for resource_cfg in resource_configs:
            resource = resource_cfg["Type"]
            if not is_kubernetes_builtin_resource(resource):
                crd_rule = {
                    "resources": [resource],
                    "objectSelectors": [{"matchLabels": workload_labels}],
                    "apiGroup": get_api_group_for_crd(resource, crd_api_groups)
                }
                if resource_cfg.get("CreateOnly"):
                    crd_rule["createOnly"] = True
                if namespaces_to_sync:
                    crd_rule["namespaces"] = namespaces_to_sync
                downsync_rules.insert(0, crd_rule)  # Insert at beginning

        # Handle built-in resources
        for resource_cfg in resource_configs:
            resource = resource_cfg["Type"]
            if resource == "namespaces":
                continue
            if is_kubernetes_builtin_resource(resource):
                rule = {
                    "resources": [resource],
                    "objectSelectors": [{"matchLabels": workload_labels}]
                }
                if resource_cfg.get("CreateOnly"):
                    rule["createOnly"] = True
                if namespaces_to_sync:
                    rule["namespaces"] = namespaces_to_sync
                downsync_rules.append(rule)

        # Always add namespaces first if present
        if any(cfg["Type"] == "namespaces" for cfg in resource_configs):
            ns_rule = {
                "resources": ["namespaces"],
                "objectSelectors": [{"matchLabels": workload_labels}]
            }
            if namespaces_to_sync:
                ns_rule["namespaces"] = namespaces_to_sync
            downsync_rules.insert(0, ns_rule)

        # Build the BindingPolicy object
        policy_obj = {
            "apiVersion": "control.kubestellar.io/v1alpha1",
            "kind": "BindingPolicy",
            "metadata": {
                "name": policy_name
                # Note: no namespace field since this is cluster-scoped
            },
            "spec": {
                "downsync": downsync_rules,
                "clusterSelectors": [{"matchLabels": cluster_labels}],
                "bindingMode": "Downsync"
            }
        }

        print(f"Creating cluster-scoped policy: {yaml.dump(policy_obj)}")

        try:
            # Create the policy as a cluster-scoped resource
            result = api.create_cluster_custom_object(
                group="control.kubestellar.io",
                version="v1alpha1",
                plural="bindingpolicies",
                body=policy_obj
            )
        except client.exceptions.ApiException as e:
            return {
                "error": f"Kubernetes API error: {e.status}",
                "message": str(e),
                "details": e.body if hasattr(e, 'body') else "No details available"
            }

        # Prepare response
        response = {
            "message": f"Created cluster-scoped binding policy '{policy_name}' successfully",
            "bindingPolicy": {
                "name": policy_name,
                "status": "inactive",
                "bindingMode": "Downsync",
                "clusters": format_labels(cluster_labels),
                "workloads": [cfg["Type"] for cfg in resource_configs],
                "clustersCount": len(cluster_labels),
                "workloadsCount": len(resource_configs),
                "yaml": yaml.dump(policy_obj)
            }
        }
        return response

    except client.exceptions.ApiException as e:
        return {
            "error": f"Kubernetes API error: {e.status}",
            "message": str(e),
            "details": e.body if hasattr(e, 'body') else "No details available"
        }
    except Exception as e:
        return {
            "error": str(e),
            "message": "Failed to create the BindingPolicy. Please check the input parameters and cluster configuration."
        }

@mcp.tool()
async def create_binding_policy(
    policy_name: str,
    namespace: str,
    cluster_labels: Dict[str, str],
    workload_labels: Dict[str, str],
    resource_configs: List[Dict[str, Any]],
    crd_api_groups: Dict[str, str],
    namespaces_to_sync: Optional[List[str]] = None,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a BindingPolicy CRD in the target cluster.
    
    Args:
        policy_name: Name of the binding policy
        namespace: Namespace to create the policy in (ignored for cluster-scoped policies)
        cluster_labels: Labels to select target clusters
        workload_labels: Labels to select target workloads
        resource_configs: List of resource configurations
        crd_api_groups: API groups for CRDs
        namespaces_to_sync: Optional list of namespaces to sync
        context: Kubernetes context to use
    
    Returns:
        Dict with result or error information
    """
    try:
        # Validate inputs
        if not policy_name:
            return {
                "error": "Invalid input",
                "message": "Policy name cannot be empty"
            }
        
        if not isinstance(cluster_labels, dict):
            return {
                "error": "Invalid input",
                "message": "cluster_labels must be a dictionary"
            }
        
        if not isinstance(workload_labels, dict):
            return {
                "error": "Invalid input",
                "message": "workload_labels must be a dictionary"
            }
        
        if not isinstance(resource_configs, list):
            return {
                "error": "Invalid input",
                "message": "resource_configs must be a list"
            }

        # Load kube config and verify context
        current_context = load_kube_config(context)
        print(f"Using context: {current_context['name']}")
        
        # Check if policy already exists
        api = client.CustomObjectsApi()
        try:
            api.get_cluster_custom_object(
                group="control.kubestellar.io",
                version="v1alpha1",
                plural="bindingpolicies",
                name=policy_name
            )
            return {
                "error": "Policy already exists",
                "message": f"Binding policy '{policy_name}' already exists"
            }
        except client.exceptions.ApiException as e:
            if e.status != 404:
                raise

        # Build downsync rules
        downsync_rules = []
        for resource_cfg in resource_configs:
            if not isinstance(resource_cfg, dict) or "Type" not in resource_cfg:
                return {
                    "error": "Invalid resource config",
                    "message": f"Invalid resource configuration: {resource_cfg}"
                }
            
            resource = resource_cfg["Type"]
            rule = {
                "resources": [resource],
                "objectSelectors": [{"matchLabels": workload_labels}],
                "apiGroup": get_api_group_for_crd(resource, crd_api_groups)
            }
            if resource_cfg.get("CreateOnly"):
                rule["createOnly"] = True
            if namespaces_to_sync:
                rule["namespaces"] = namespaces_to_sync
            downsync_rules.append(rule)

        # Build the BindingPolicy object
        policy_obj = {
            "apiVersion": "control.kubestellar.io/v1alpha1",
            "kind": "BindingPolicy",
            "metadata": {
                "name": policy_name
            },
            "spec": {
                "downsync": downsync_rules,
                "clusterSelectors": [{"matchLabels": cluster_labels}],
                "bindingMode": "Downsync"
            }
        }

        print(f"Creating binding policy: {yaml.dump(policy_obj)}")

        try:
            # Create the policy
            result = api.create_cluster_custom_object(
                group="control.kubestellar.io",
                version="v1alpha1",
                plural="bindingpolicies",
                body=policy_obj
            )
            
            # Prepare response
            response = {
                "message": f"Created binding policy '{policy_name}' successfully",
                "bindingPolicy": {
                    "name": policy_name,
                    "status": "inactive",
                    "bindingMode": "Downsync",
                    "clusters": format_labels(cluster_labels),
                    "workloads": [cfg["Type"] for cfg in resource_configs],
                    "clustersCount": len(cluster_labels),
                    "workloadsCount": len(resource_configs),
                    "yaml": yaml.dump(policy_obj)
                }
            }
            return response

        except client.exceptions.ApiException as e:
            return {
                "error": f"Kubernetes API error: {e.status}",
                "message": str(e),
                "details": e.body if hasattr(e, 'body') else "No details available"
            }

    except client.exceptions.ApiException as e:
        return {
            "error": f"Kubernetes API error: {e.status}",
            "message": str(e),
            "details": e.body if hasattr(e, 'body') else "No details available"
        }
    except Exception as e:
        return {
            "error": str(e),
            "message": "Failed to create the BindingPolicy. Please check the input parameters and cluster configuration."
        }

@mcp.tool()
async def list_binding_policies(
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    List all BindingPolicy CRDs in the cluster.
    """
    try:
        load_kube_config(context)
        api = client.CustomObjectsApi()

        try:
            # Get all binding policies
            policies = api.list_cluster_custom_object(
                group="control.kubestellar.io",
                version="v1alpha1",
                plural="bindingpolicies"
            )

            # Parse and format the policies
            policies_list = []
            for policy in policies.get('items', []):
                policy_data = {
                    "name": policy.get('metadata', {}).get('name', ''),
                    "age": policy.get('metadata', {}).get('creationTimestamp', ''),
                    "status": policy.get('status', {}).get('conditions', [{}])[0].get('status', ''),
                    "clusterSelectors": policy.get('spec', {}).get('clusterSelectors', []),
                    "downsync": policy.get('spec', {}).get('downsync', []),
                    "bindingMode": policy.get('spec', {}).get('bindingMode', '')
                }
                policies_list.append(policy_data)

            return {
                "message": "Successfully retrieved binding policies",
                "bindingPolicies": policies_list,
                "totalPolicies": len(policies_list)
            }

        except client.exceptions.ApiException as e:
            return {
                "error": f"Kubernetes API error: {e.status}",
                "message": str(e),
                "details": e.body if hasattr(e, 'body') else "No details available"
            }

    except Exception as e:
        return {
            "error": str(e),
            "message": "Failed to list binding policies. Please check the cluster configuration."
        }

@mcp.tool()
async def delete_binding_policy(
    policy_name: str,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Delete a BindingPolicy CRD from the cluster.
    """
    try:
        load_kube_config(context)
        api = client.CustomObjectsApi()

        try:
            result = api.delete_cluster_custom_object(
                group="control.kubestellar.io",
                version="v1alpha1",
                plural="bindingpolicies",
                name=policy_name,
                body=client.V1DeleteOptions()
            )
            return {
                "message": f"Binding policy '{policy_name}' deleted successfully",
                "deletedPolicy": {
                    "name": policy_name,
                    "status": "deleted"
                }
            }
        except client.exceptions.ApiException as e:
            if e.status == 404:
                return {
                    "message": f"Binding policy '{policy_name}' not found"
                }
            raise

    except client.exceptions.ApiException as e:
        return {
            "error": f"Kubernetes API error: {e.status}",
            "message": str(e),
            "details": e.body if hasattr(e, 'body') else "No details available"
        }
    except Exception as e:
        return {
            "error": str(e),
            "message": "Failed to delete the BindingPolicy. Please check the input parameters and cluster configuration."
        }

@mcp.tool()
async def get_binding_policy_details(
    policy_name: str,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get detailed information about a specific BindingPolicy CRD.
    """
    try:
        load_kube_config(context)
        api = client.CustomObjectsApi()

        try:
            # Get the specific binding policy
            policy = api.get_cluster_custom_object(
                group="control.kubestellar.io",
                version="v1alpha1",
                plural="bindingpolicies",
                name=policy_name
            )

            # Parse and format the policy details
            policy_data = {
                "metadata": {
                    "name": policy.get('metadata', {}).get('name', ''),
                    "namespace": policy.get('metadata', {}).get('namespace', ''),
                    "creationTimestamp": policy.get('metadata', {}).get('creationTimestamp', ''),
                    "uid": policy.get('metadata', {}).get('uid', '')
                },
                "spec": {
                    "bindingMode": policy.get('spec', {}).get('bindingMode', ''),
                    "clusterSelectors": policy.get('spec', {}).get('clusterSelectors', []),
                    "downsync": policy.get('spec', {}).get('downsync', []),
                    "wantSingletonReportedState": policy.get('spec', {}).get('wantSingletonReportedState', False)
                },
                "status": {
                    "conditions": policy.get('status', {}).get('conditions', []),
                    "errors": policy.get('status', {}).get('errors', []),
                    "observedGeneration": policy.get('status', {}).get('observedGeneration', 0)
                }
            }

            return {
                "message": f"Successfully retrieved details for binding policy '{policy_name}'",
                "bindingPolicy": policy_data
            }

        except client.exceptions.ApiException as e:
            if e.status == 404:
                return {
                    "error": f"Binding policy '{policy_name}' not found",
                    "message": "The specified binding policy does not exist in the cluster"
                }
            return {
                "error": f"Kubernetes API error: {e.status}",
                "message": str(e),
                "details": e.body if hasattr(e, 'body') else "No details available"
            }

    except Exception as e:
        return {
            "error": str(e),
            "message": "Failed to get binding policy details. Please check the input parameters and cluster configuration."
        }
    
@mcp.tool()
async def get_binding_policy_status(
    policy_name: str,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get the status of a specific BindingPolicy CRD.
    """
    try:
        load_kube_config(context)
        api = client.CustomObjectsApi()

        try:
            # Get the specific binding policy
            policy = api.get_cluster_custom_object(
                group="control.kubestellar.io",
                version="v1alpha1",
                plural="bindingpolicies",
                name=policy_name
            )

            # Parse and format the policy status
            status_data = {
                "status": policy.get('status', {}),
                "conditions": policy.get('status', {}).get('conditions', []),
                "errors": policy.get('status', {}).get('errors', [])
            }

            return {
                "message": f"Successfully retrieved status for binding policy '{policy_name}'",
                "bindingPolicyStatus": status_data
            }

        except client.exceptions.ApiException as e:
            if e.status == 404:
                return {
                    "error": f"Binding policy '{policy_name}' not found",
                    "message": "The specified binding policy does not exist in the cluster"
                }
            return {
                "error": f"Kubernetes API error: {e.status}",
                "message": str(e),
                "details": e.body if hasattr(e, 'body') else "No details available"
            }

    except Exception as e:
        return {
            "error": str(e),
            "message": "Failed to get binding policy status. Please check the input parameters and cluster configuration."
        }


# LABELSSSSSSSS

def load_kube_config(context: Optional[str] = None):
    """Load kubeconfig for a given context."""
    config.load_kube_config(context=context)

@mcp.tool()
async def list_pods(namespace: str = "default", label_selector: Optional[str] = None,
              field_selector: Optional[str] = None, context: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List pods in a namespace.
    Returns a list of pod dictionaries.
    """
    load_kube_config(context)
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace=namespace, label_selector=label_selector, field_selector=field_selector)
    return [pod.to_dict() for pod in pods.items]

@mcp.tool()
async def get_current_context() -> str:
    """Get the current kubeconfig context."""
    load_kube_config()
    config_obj = config.kube_config.KubeConfigManager().get_current_context()
    return config_obj

@mcp.tool()
async def switch_context(context: str) -> None:
    """Switch kubeconfig context."""
    load_kube_config()
    config_obj = config.kube_config.KubeConfigManager()
    config_obj.set_current_context(context)

@mcp.tool()
async def get_current_cluster() -> str:
    """Get the current cluster name."""
    load_kube_config()
    config_obj = config.kube_config.KubeConfigManager().get_current_context()
    return config_obj['context']['cluster']

@mcp.tool()
async def get_current_user() -> str:
    """Get the current user name."""
    load_kube_config()
    config_obj = config.kube_config.KubeConfigManager().get_current_context()
    return config_obj['context']['user']
@mcp.tool()
async def get_current_namespace() -> str:
    """Get the current namespace."""
    load_kube_config()
    config_obj = config.kube_config.KubeConfigManager().get_current_context()
    return config_obj['context'].get('namespace', 'default')
@mcp.tool()
async def create_namespace(namespace: str) -> None:
    """Create a new namespace."""
    load_kube_config()
    v1 = client.CoreV1Api()
    body = client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace))
    v1.create_namespace(body)
@mcp.tool()
async def delete_namespace(namespace: str) -> None:
    """Delete a namespace."""
    load_kube_config()
    v1 = client.CoreV1Api()
    v1.delete_namespace(name=namespace, body=client.V1DeleteOptions())
@mcp.tool()
async def get_all_namespaces() -> List[str]:
    """Get all namespaces."""
    load_kube_config()
    v1 = client.CoreV1Api()
    namespaces = v1.list_namespace()
    return [ns.metadata.name for ns in namespaces.items]
@mcp.tool()
async def switch_namespace(namespace: str) -> None:
    """Switch the current namespace."""
    load_kube_config()
    config_obj = config.kube_config.KubeConfigManager()
    context = config_obj.get_current_context()
    context['context']['namespace'] = namespace
    config_obj.set_current_context(context)

@mcp.tool()
async def create_cluster(cluster_name: str, context: str) -> None:
    """Create a new cluster."""
    load_kube_config()
    config_obj = config.kube_config.KubeConfigManager()
    config_obj.create_cluster(cluster_name, context)
@mcp.tool()
async def delete_cluster(cluster_name: str) -> None:
    """Delete a cluster."""
    load_kube_config()
    config_obj = config.kube_config.KubeConfigManager()
    config_obj.delete_cluster(cluster_name)
@mcp.tool()
async def get_all_clusters() -> List[str]:
    """Get all clusters."""
    load_kube_config()
    config_obj = config.kube_config.KubeConfigManager()
    clusters = config_obj.get_all_clusters()
    return [cluster['name'] for cluster in clusters]
@mcp.tool()
async def get_nodes() -> List[str]:
    """Get all nodes."""
    load_kube_config()
    v1 = client.CoreV1Api()
    nodes = v1.list_node()
    return [node.metadata.name for node in nodes.items]
@mcp.tool()
async def get_node_info(node_name: str) -> Dict[str, Any]:
    """Get information about a specific node."""
    load_kube_config()
    v1 = client.CoreV1Api()
    node = v1.read_node(name=node_name)
    return node.to_dict()
@mcp.tool()
async def get_all_labels() -> List[str]:
    """Get all labels."""
    load_kube_config()
    v1 = client.CoreV1Api()
    nodes = v1.list_node()
    labels = set()
    for node in nodes.items:
        labels.update(node.metadata.labels.keys())
    return list(labels)
@mcp.tool()
async def update_labels(node_name: str, labels: Dict[str, str]) -> None:
    """Update labels on a node."""
    load_kube_config()
    v1 = client.CoreV1Api()
    node = v1.read_node(name=node_name)
    node.metadata.labels.update(labels)
    v1.patch_node(name=node_name, body=node)
@mcp.tool()
async def delete_labels(node_name: str, labels: List[str]) -> None:
    """Delete labels from a node."""
    load_kube_config()
    v1 = client.CoreV1Api()
    node = v1.read_node(name=node_name)
    for label in labels:
        if label in node.metadata.labels:
            del node.metadata.labels[label]
    v1.patch_node(name=node_name, body=node)
if __name__ == "__main__":
    mcp.run(transport="stdio") 