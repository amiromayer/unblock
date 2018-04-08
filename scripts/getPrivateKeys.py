from btcutils import Wallet
from network import BitcoinTestNet
from network import BitcoinMainNet

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

network = BitcoinMainNet

n = int(input(bcolors.OKGREEN + "\nEnter the number of addresses to get private keys for: " + bcolors.OKBLUE))
print(bcolors.ENDC)

parent_private_key = input(bcolors.OKGREEN + "Enter the parent's private key (xpriv) to get child private keys for: \n" + bcolors.OKBLUE)
print(bcolors.ENDC)

user_wallets = []
user_xpublic_keys = []
user_xprivate_keys = []
payment_adresses = []
user_private_keys = []

wallet = Wallet.deserialize(parent_private_key, network = network)
private_key = wallet.serialize_b58(private=True)
public_key = wallet.public_copy().serialize_b58(private=False)

# Creates new user wallet
def newUserWallet():
    user_wallets.append(wallet.get_child(user_id))
    user_xprivate_keys.append(user_wallets[user_id].serialize_b58(private=True))
    user_xpublic_keys.append(user_wallets[user_id].public_copy().serialize_b58(private=False))
    user_private_keys.append(user_wallets[user_id].export_to_wif())
    payment_adresses.append(user_wallets[user_id].to_address())
    return;

# Gets bitcoin payment address for a given user_id
def getAddress(user_id):
    return payment_adresses[user_id]

# Gets private key for a given user_id
def getPrivateKey(user_id):
    return user_private_keys[user_id]

# Generates (n-1) addresses using
for user_id in range(n):
    newUserWallet()

print(bcolors.BOLD + "Generated Adresses: " + bcolors.ENDC)
print("----------------------------------")
for user_id in range(n):
    print(bcolors.OKGREEN + payment_adresses[user_id] + bcolors.ENDC)
print("----------------------------------\n")

print(bcolors.BOLD + "WIF Private Keys: " + bcolors.ENDC)
print("----------------------------------------------------")
for user_id in range(n):
    print(bcolors.OKGREEN + user_private_keys[user_id] + bcolors.ENDC)
print("----------------------------------------------------\n")

print(bcolors.BOLD + "\nExtended Public Keys (xpubs): " + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------")
for user_id in range(n):
    print(bcolors.OKGREEN + user_xpublic_keys[user_id] + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------\n")

print(bcolors.BOLD + "Extended Private Keys (xprivs): " + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------")
for user_id in range(n):
    print(bcolors.OKGREEN + user_xprivate_keys[user_id] + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------\n")
