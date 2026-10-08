def encrypt(string, shift):
    result = ''
    for char in string:
        if char.isalpha() and char.isascii():
            shift_amount = shift % 26
            if char.islower():
                new_char = chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
            else:
                new_char = chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
            result += new_char
        else:
            result += char
    return result

def decrypt(string, shift):
    result = ''
    for char in string:
        if char.isalpha() and char.isascii():
            shift_amount = shift % 26
            if char.islower():
                new_char = chr((ord(char) - ord('a') - shift_amount) % 26 + ord('a'))
            else:
                new_char = chr((ord(char) - ord('A') - shift_amount) % 26 + ord('A'))
            result += new_char
        else:
            result += char
    return result

def decrypt_without_key(string):
    letter_count = {chr(ord('a') + a): 0 for a in range(26)}
    for char in string:
        if char.isalpha() and char.isascii():
            if char.islower():
                letter_count[char] += 1
            else:
                letter_count[char.lower()] += 1

    if not any(letter_count.values()):
        return string

    most_common_letter = max(letter_count, key=letter_count.get)
    shift = (ord(most_common_letter) - ord('e')) % 26
    return decrypt(string, shift)


if __name__ == '__main__':
    # Check uppercase letters, wraparound, punctuation, and empty input.
    assert encrypt('Abc Xyz!', 3) == 'Def Abc!'
    assert decrypt('Def Abc!', 3) == 'Abc Xyz!'
    assert encrypt('Abc Xyz!', -3) == 'Xyz Uvw!'
    assert encrypt('Abc Xyz!', 29) == 'Def Abc!'
    assert encrypt('', 3) == ''
    assert decrypt('', 3) == ''
    assert decrypt_without_key('') == ''
    assert decrypt_without_key('123, !') == '123, !'
    assert decrypt_without_key('Ll l!') == 'Ee e!'

    # Use an English paragraph where 'e' is the most frequent letter.
    paragraph = (
        'Every evening, we meet near the green trees beside the river. '
        'We share ideas, tell stories, and remember the lessons we learned. '
        'These peaceful meetings help everyone feel connected and keep '
        'our friendships strong.'
    )
    shift = 7
    encrypted = encrypt(paragraph, shift)
    decrypted = decrypt(encrypted, shift)
    recovered = decrypt_without_key(encrypted)

    print('Original paragraph:', paragraph)
    print('Encrypted paragraph:', encrypted)
    print('Decrypted with the key:', decrypted)
    print('Decrypted without the key:', recovered)

    assert decrypted == paragraph
    assert recovered == paragraph
    print('All tests passed.')
