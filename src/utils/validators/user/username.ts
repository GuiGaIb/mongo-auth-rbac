/**
 * Default username validator function.
 * This validator checks that the username contains only letters (including accented characters) and spaces.
 * @param u
 * @returns
 */
export function usernameValidator(u: string): boolean {
    return !!u.match(/^[a-zA-ZÀ-ÖØ-öø-ÿ ]+$/);
}
