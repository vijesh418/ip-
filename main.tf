locals {
  master = {
    atlantis = [
      "1.1.1.0/24", # atlantis
    ]
    common_aks = [
      "99.99.96.0/21", # gcssre-dev-gdo-aks
      "2.0.0.0/10"    # gcssre-prd-gdo-aks
    ]
  }
}