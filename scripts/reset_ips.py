#!/usr/bin/env python3
import os
import json
from concurrent.futures import ThreadPoolExecutor
from azure.identity import ClientSecretCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.keyvault import KeyVaultManagementClient

def get_azure_client():
    creds = json.loads(os.environ['AZURE_CREDENTIALS'])
    credential = ClientSecretCredential(
        tenant_id=creds['tenantId'],
        client_id=creds['clientId'],
        client_secret=creds['clientSecret']
    )
    return credential, creds['subscriptionId']

def parse_baseline_ips():
    return [ip.strip() for ip in os.environ['TERRAFORM_BASELINE'].split(',') if ip.strip()]

def should_keep_ip(current_ip, baseline_ips):
    for baseline in baseline_ips:
        if current_ip == baseline or current_ip == f"{baseline}/32" or f"{current_ip}/32" == baseline:
            return True
    return False

def reset_storage_accounts():
    credential, subscription_id = get_azure_client()
    client = StorageManagementClient(credential, subscription_id)
    resource_group = os.environ['RESOURCE_GROUP']
    baseline_ips = parse_baseline_ips()
    
    accounts = list(client.storage_accounts.list_by_resource_group(resource_group))
    
    def process_account(account):
        try:
            current_rules = client.storage_accounts.get_properties(resource_group, account.name).network_rule_set.ip_rules
            current_ips = [rule.ip_address_or_range for rule in current_rules] if current_rules else []
            
            keep_ips = [ip for ip in current_ips if should_keep_ip(ip, baseline_ips)]
            
            # Update network rules
            from azure.mgmt.storage.models import StorageAccountUpdateParameters, NetworkRuleSet, IPRule
            update_params = StorageAccountUpdateParameters(
                network_rule_set=NetworkRuleSet(
                    default_action='Allow' if not keep_ips else 'Deny',
                    ip_rules=[IPRule(ip_address_or_range=ip) for ip in keep_ips]
                )
            )
            
            client.storage_accounts.update(resource_group, account.name, update_params)
            print(f"✓ Storage: {account.name} - kept {len(keep_ips)} IPs")
        except Exception as e:
            print(f"✗ Storage: {account.name} - {e}")
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(process_account, accounts))

def reset_aks_clusters():
    credential, subscription_id = get_azure_client()
    client = ContainerServiceClient(credential, subscription_id)
    resource_group = os.environ['RESOURCE_GROUP']
    baseline_ips = parse_baseline_ips()
    
    clusters = list(client.managed_clusters.list_by_resource_group(resource_group))
    
    def process_cluster(cluster):
        try:
            current_ips = cluster.api_server_access_profile.authorized_ip_ranges if cluster.api_server_access_profile else []
            keep_ips = [ip for ip in current_ips if should_keep_ip(ip, baseline_ips)]
            
            # Update authorized IP ranges using PATCH operation
            from azure.mgmt.containerservice.models import ManagedCluster, ManagedClusterAPIServerAccessProfile
            cluster_update = ManagedCluster(
                api_server_access_profile=ManagedClusterAPIServerAccessProfile(
                    authorized_ip_ranges=keep_ips if keep_ips else []
                )
            )
            
            client.managed_clusters.begin_update_tags(resource_group, cluster.name, cluster_update).wait()
            print(f"✓ AKS: {cluster.name} - kept {len(keep_ips)} IPs")
        except Exception as e:
            print(f"✗ AKS: {cluster.name} - {e}")
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(process_cluster, clusters))

def reset_key_vaults():
    credential, subscription_id = get_azure_client()
    client = KeyVaultManagementClient(credential, subscription_id)
    resource_group = os.environ['RESOURCE_GROUP']
    baseline_ips = parse_baseline_ips()
    
    vaults = list(client.vaults.list_by_resource_group(resource_group))
    
    def process_vault(vault):
        try:
            current_ips = []
            if vault.properties.network_acls and vault.properties.network_acls.ip_rules:
                current_ips = [rule.value for rule in vault.properties.network_acls.ip_rules]
            
            keep_ips = [ip for ip in current_ips if ip in baseline_ips]  # Exact match for KV
            
            # Update network ACLs
            from azure.mgmt.keyvault.models import VaultCreateOrUpdateParameters, VaultProperties, NetworkRuleSet, IPRule
            vault_params = VaultCreateOrUpdateParameters(
                location=vault.location,
                properties=VaultProperties(
                    tenant_id=vault.properties.tenant_id,
                    sku=vault.properties.sku,
                    network_acls=NetworkRuleSet(
                        default_action='Allow' if not keep_ips else 'Deny',
                        ip_rules=[IPRule(value=ip) for ip in keep_ips]
                    )
                )
            )
            
            client.vaults.create_or_update(resource_group, vault.name, vault_params)
            print(f"✓ KeyVault: {vault.name} - kept {len(keep_ips)} IPs")
        except Exception as e:
            print(f"✗ KeyVault: {vault.name} - {e}")
    
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(process_vault, vaults))

def main():
    print(f"Resetting resources in {os.environ['RESOURCE_GROUP']} to baseline...")
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(reset_storage_accounts),
            executor.submit(reset_aks_clusters),
            executor.submit(reset_key_vaults)
        ]
        
        for future in futures:
            future.result()
    
    print("Reset complete!")

if __name__ == "__main__":
    main()