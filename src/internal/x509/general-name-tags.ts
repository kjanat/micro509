/**
 * The DER wire tags of the nine GeneralName CHOICE alternatives (RFC 5280
 * §4.2.1.6), fixing tag class, number, and constructedness.
 *
 * @module
 */

/**
 * Valid GeneralName tags: `otherName [0]`, `rfc822Name [1]`, `dNSName [2]`,
 * `x400Address [3]`, `directoryName [4]`, `ediPartyName [5]`,
 * `uniformResourceIdentifier [6]`, `iPAddress [7]`, `registeredID [8]`. Any
 * other tag, class, or constructedness is not a GeneralName.
 */
export const GENERAL_NAME_WIRE_TAGS: ReadonlySet<number> = new Set([
	0xa0, 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88,
]);
