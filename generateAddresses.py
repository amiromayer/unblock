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

n = int(input(bcolors.OKGREEN + "\nEnter the number of addresses to generate: " + bcolors.OKBLUE))
print(bcolors.ENDC)

parent_public_key = input(bcolors.OKGREEN + "Enter the parent's public key (xpub) to generate adresses from: \n" + bcolors.OKBLUE)
print(bcolors.ENDC)

# parent_public_key = "xpub68orFewRquxzfG7p5kbp95jTbRD5uoJTxmQ6ns337NDc5KZrKBqYnoHpkrrwdKZRXE1QgpLy1MC6MVaqtH8mqFhPaF3EXe7MPh1XLr7HjzY"

wallet = Wallet.deserialize(parent_public_key, network = network)
public_key = wallet.public_copy().serialize_b58(private=False)

user_wallets = []
user_xpublic_keys = []
payment_adresses = []

# Creates new user wallet
def newUserWallet():
    user_wallets.append(wallet.create_new_address_for_user(user_id))
    payment_adresses.append(user_wallets[user_id].to_address())
    return;

# Gets bitcoin payment address for a given user_id
def getAddress(user_id):
    return payment_adresses[user_id]

# Generates (n-1) addresses using
for user_id in range(n):
    newUserWallet()

print(bcolors.BOLD + "Parent's Public Key:" + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------")
print(bcolors.OKGREEN + parent_public_key + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------\n")

print(bcolors.BOLD + "Generated Adresses:" + bcolors.ENDC)
print("----------------------------------")
for user_id in range(n):
    print(bcolors.OKGREEN + payment_adresses[user_id] + bcolors.ENDC)
print("----------------------------------")
