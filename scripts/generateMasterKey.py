from btcutils import Wallet
from network import BitcoinMainNet
from network import BitcoinTestNet

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
seed = input(bcolors.OKGREEN + "\nPlease enter your seed: " + bcolors.ENDC)

master_wallet = Wallet.from_master_secret(seed = seed, network = network)
master_private_key = master_wallet.serialize_b58(private=True)
master_public_key = master_wallet.public_copy().serialize_b58(private=False)

print(bcolors.FAIL + "\nWarning! Keep your master keys secret.\n" + bcolors.ENDC)

print(bcolors.BOLD + "Master Private Key: " + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------")
print(bcolors.OKGREEN + master_private_key + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------\n")

print(bcolors.BOLD + "Master Public Key: " + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------")
print(bcolors.OKGREEN + master_public_key + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------")

print(bcolors.OKBLUE)
print("If you want to use the convenience of an xpub to derive branches of public keys, without exposing yourself ")
print("to the risk of a leaked chain code, you should derive it from a hardened parent, rather than a normal parent.")
print("As a best practice, the level-1 children of the master keys are always derived through the hardened derivation, ")
print("to prevent compromise of the master keys.")

print(bcolors.WARNING)
print("\nYou can can load the following extended public key (xpub) on your website, which can be used ")
print("to derive a unique address for every customer order.")
print(bcolors.ENDC)

child_wallet = master_wallet.get_child(0, is_prime=True, as_private=True)
child_private_key = child_wallet.serialize_b58(private=True)
child_public_key = child_wallet.public_copy().serialize_b58(private=False)


print(bcolors.BOLD + "Master Prime Child Private Key: " + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------")
print(bcolors.OKGREEN + child_private_key + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------\n")

print(bcolors.BOLD + "Master Prime Child Public Key: " + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------")
print(bcolors.OKGREEN + child_public_key + bcolors.ENDC)
print("---------------------------------------------------------------------------------------------------------------\n")
