import argparse, secrets, string

parser = argparse.ArgumentParser(prog='OTP-Key-Generator', description='This program can generate secure and random keys for OTP')
parser.add_argument('-n', '--number', help='The number of keys', required=True, metavar='<number>', type=int)
parser.add_argument('-x', '--hex', action='store_true', help='Create hexadecimal keys')
parser.add_argument('-o', '--output', help='The name of output file', metavar='<file>', required=True)
parser.add_argument('-l', '--length', help='The length of generated keys', metavar='<length>', required=True, type=int)
args = parser.parse_args()

KEY_LETTERS = tuple(string.ascii_letters + string.punctuation + string.digits)

def create_random_key():
    key = ''
    key_length = args.length
    if not args.hex:
        for i in range(key_length):
            key += secrets.choice(KEY_LETTERS)
    else:
        key = secrets.token_hex(key_length)
    return key

if __name__ == '__main__':
    print('Generating Keys ...')
    with open(args.output, 'w') as f:
        for i in range(1, args.number+1):
            print(f'{i}/{args.number}', end='\r')
            f.write(create_random_key() + '\n\n')
    print('Done.' + ' ' * (len(f'{args.number}/{args.number}') - 5))
