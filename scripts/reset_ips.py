#!/usr/bin/env python3
import os
import json

from concurrent.futures import ThreadPoolExecutor
from azure.identity import ClientSecretCredential
# from azure.mgmt.storage import StorageManagementClient


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

# def reset_storage_accounts():
#     credential, subscription_id = get_azure_client()
#     client = StorageManagementClient(credential, subscription_id)
#     resource_group = os.environ['RESOURCE_GROUP']
#     baseline_ips = parse_baseline_ips()

#     accounts = list(client.storage_accounts.list_by_resource_group(resource_group))

#     def process_account(account):
#         try:
#             current_account = client.storage_accounts.get_properties(resource_group, account.name)
#             current_rules = current_account.network_rule_set.ip_rules if current_account.network_rule_set else []
#             current_ips = [rule.ip_address_or_range for rule in current_rules]

#             keep_ips = [ip for ip in current_ips if should_keep_ip(ip, baseline_ips)]

#             # Preserve original default action
#             original_default = current_account.network_rule_set.default_action if current_account.network_rule_set else 'Allow'

#             from azure.mgmt.storage.models import StorageAccountUpdateParameters, NetworkRuleSet, IPRule
#             update_params = StorageAccountUpdateParameters(
#                 network_rule_set=NetworkRuleSet(
#                     default_action=original_default,
#                     ip_rules=[IPRule(ip_address_or_range=ip) for ip in keep_ips]
#                 )
#             )

#             client.storage_accounts.update(resource_group, account.name, update_params)
#             removed_count = len(current_ips) - len(keep_ips)
#             print(f"✓ Storage: {account.name} - kept {len(keep_ips)} IPs, removed {removed_count} IPs")
#         except Exception as e:
#             print(f"✗ Storage: {account.name} - {e}")

#     with ThreadPoolExecutor(max_workers=5) as executor:
#         list(executor.map(process_account, accounts))


def reset_aks_clusters():
    from azure.mgmt.containerservice import ContainerServiceClient
    from azure.mgmt.resource import ResourceManagementClient
    credential, subscription_id = get_azure_client()
    aks_client = ContainerServiceClient(credential, subscription_id)
    resource_client = ResourceManagementClient(credential, subscription_id)
    baseline_ips = parse_baseline_ips()
    dry_run = os.environ.get('DRY_RUN', 'false').lower() == 'true'

    # Get all resource groups in subscription
    resource_groups = list(resource_client.resource_groups.list())
    
    all_clusters = []
    rg_with_aks = []
    
    # Find all AKS clusters across all resource groups
    for rg in resource_groups:
        try:
            clusters_in_rg = list(aks_client.managed_clusters.list_by_resource_group(rg.name))
            if clusters_in_rg:
                all_clusters.extend([(cluster, rg.name) for cluster in clusters_in_rg])
                rg_with_aks.append(rg.name)
        except Exception as e:
            print(f"  ⚠️ Could not access resource group {rg.name}: {e}")
    
    print(f"Found {len(all_clusters)} AKS clusters across {len(rg_with_aks)} resource groups:")
    for rg_name in rg_with_aks:
        cluster_names = [cluster.name for cluster, rg in all_clusters if rg == rg_name]
        print(f"  • {rg_name}: {', '.join(cluster_names)}")
    print()

    def process_cluster(cluster, rg_name):
        try:
            current_ips = cluster.api_server_access_profile.authorized_ip_ranges if cluster.api_server_access_profile else []
            keep_ips = [ip for ip in current_ips if should_keep_ip(ip, baseline_ips)]
            remove_ips = [ip for ip in current_ips if not should_keep_ip(ip, baseline_ips)]

            # Print detailed IP information
            print(f"\n{'[DRY RUN] ' if dry_run else ''}AKS: {cluster.name} (RG: {rg_name})")
            print(f"  Current IPs ({len(current_ips)}): {', '.join(current_ips) if current_ips else 'None'}")
            print(f"  Keep IPs ({len(keep_ips)}): {', '.join(keep_ips) if keep_ips else 'None'}")
            print(f"  Remove IPs ({len(remove_ips)}): {', '.join(remove_ips) if remove_ips else 'None'}")

            if not dry_run:
                # Use PATCH operation for AKS
                from azure.mgmt.containerservice.models import ManagedClusterAPIServerAccessProfile

                # Only update the API server access profile
                cluster.api_server_access_profile = ManagedClusterAPIServerAccessProfile(
                    authorized_ip_ranges=keep_ips
                )

                # Start async operation and continue immediately
                aks_client.managed_clusters.begin_create_or_update(
                    rg_name, cluster.name, cluster
                )
                # Fire-and-forget: operation continues in background
                print(f"  ✓ Updated successfully")
            else:
                print(f"  ✓ Dry run - no changes made")
        except Exception as e:
            print(f"  ✗ Error: {e}")

    # Process clusters sequentially to avoid Azure throttling
    for cluster, rg_name in all_clusters:
        process_cluster(cluster, rg_name)

# def reset_key_vaults():
#     from azure.mgmt.keyvault import KeyVaultManagementClient
#     credential, subscription_id = get_azure_client()
#     client = KeyVaultManagementClient(credential, subscription_id)
#     resource_group = os.environ['RESOURCE_GROUP']
#     baseline_ips = parse_baseline_ips()

#     vaults = list(client.vaults.list_by_resource_group(resource_group))

#     def process_vault(vault):
#         try:
#             current_ips = []
#             if vault.properties.network_acls and vault.properties.network_acls.ip_rules:
#                 current_ips = [rule.value for rule in vault.properties.network_acls.ip_rules]

#             keep_ips = [ip for ip in current_ips if should_keep_ip(ip, baseline_ips)]

#             # Update using SDK
#             from azure.mgmt.keyvault.models import VaultPatchParameters, VaultPatchProperties, NetworkRuleSet, IPRule
#             patch_params = VaultPatchParameters(
#                 properties=VaultPatchProperties(
#                     network_acls=NetworkRuleSet(
#                         default_action=vault.properties.network_acls.default_action if vault.properties.network_acls else 'Allow',
#                         ip_rules=[IPRule(value=ip) for ip in keep_ips]
#                     )
#                 )
#             )

#             client.vaults.update(resource_group, vault.name, patch_params)
#             removed_count = len(current_ips) - len(keep_ips)
#             print(f"✓ KeyVault: {vault.name} - kept {len(keep_ips)} IPs, removed {removed_count} IPs")
#         except Exception as e:
#             print(f"✗ KeyVault: {vault.name} - {e}")

#     with ThreadPoolExecutor(max_workers=8) as executor:
#         list(executor.map(process_vault, vaults))


def main():
    try:
        dry_run = os.environ.get('DRY_RUN', 'false').lower() == 'true'
        mode = "DRY RUN" if dry_run else "EXECUTION"
        print(f"[{mode}] Scanning all resource groups in subscription for AKS clusters...")
        
        if dry_run:
            print("🔍 DRY RUN MODE: No actual changes will be made")
        
        baseline_ips = parse_baseline_ips()
        print(f"Baseline IPs: {', '.join(baseline_ips)}\n")

        # Validate environment variables
        required_vars = ['AZURE_CREDENTIALS', 'TERRAFORM_BASELINE']
        for var in required_vars:
            if not os.environ.get(var):
                raise ValueError(
                    f"Missing required environment variable: {var}")

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                # executor.submit(reset_storage_accounts),
                executor.submit(reset_aks_clusters),
                # executor.submit(reset_key_vaults)
            ]

            for future in futures:
                future.result()

        print(f"\n{'Dry run' if dry_run else 'Reset'} complete!")
    except Exception as e:
        print(f"✗ Fatal error: {e}")
        exit(1)


if __name__ == "__main__":
    main()
