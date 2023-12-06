import argon2 from 'argon2';

/**
 * Default password validator function. This function uses a regular expression to validate the password.
 * The regex checks for the following:
 * * The password must be at least 8 characters long.
 * * The password must be at most 15 characters long.
 * * The password must contain at least one uppercase letter.
 * * The password must contain at least one lowercase letter.
 * * The password must contain at least one number.
 * * The password must contain at least one special character.
 * @param pwd Plain text password to validate
 * @returns `boolean` indicating whether the password is valid.
 */
export function rawPasswordValidator(pwd: string): boolean {
    return !!pwd.match(/^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*]).{8,15}$/);
};

/**
 * Argon2id hash validator function. This function uses the `verify` function from the `argon2` package to try to verify the hash. If no error is thrown, the hash is valid and returns `true`. If an error is thrown, the hash is invalid and returns `false`.
 * @param hash
 * @returns
 */
export async function argon2idHashValidator(hash: string): Promise<boolean> {
    try {
        await argon2.verify(hash, 'test');
        return true;
    } catch {
        return false;
    }
}
