/*!
 * Copyright(c) 2021 Ewanderson de Oliveira
 * MIT Licensed
 */

import { promisify } from 'util';
import * as Axios from 'axios';
import * as jsonwebtoken from 'jsonwebtoken';
import jwkToPem from 'jwk-to-pem';
import { ResponseBuilder } from './response-builder';


interface ConfigAuth {
    poolId: string;
    groups: string[];
    region: string;
    type: 'id' | 'access';
}

interface PublicKeyMetadata {
    instance: PublicKey;
    pem: string;
}

interface TokenHeader {
    kid: string;
    alg: string;
}
interface PublicKey {
    alg: string;
    e: string;
    kid: string;
    kty: string;
    n: string;
    use: string;
}


interface PublicKeys {
    keys: PublicKey[];
}


interface Claim {
    token_use: string;
    auth_time: number;
    iss: string;
    exp: number;
    username: string;
    client_id: string;
}

interface CacheKeys {
    [key: string]: PublicKeyMetadata;
}

const Authenticate = (config: ConfigAuth) => {
    const cognitoPoolId = config.poolId || null;
    const tokenType = config.type || 'id';
    const region = config.region || 'us-east-1'
    if (!cognitoPoolId) {
        throw new Error('missing user pool id');
    }
    const cognitoUrl = `https://cognito-idp.${region}.amazonaws.com/${cognitoPoolId}`;

    let cacheKeys: CacheKeys | undefined;

    const getPublicKeys = async (): Promise<CacheKeys> => {
        if (!cacheKeys) {
            const url = `${cognitoUrl}/.well-known/jwks.json`;
            const publicKeys = await Axios.default.get<PublicKeys>(url);
            cacheKeys = publicKeys.data.keys.reduce((agg: any, current: any) => {
                const pem = jwkToPem(current);
                agg[current.kid] = { instance: current, pem };
                return agg;
            }, {} as CacheKeys);
            return cacheKeys;
        } else {
            console.log('using cached keys');
            return cacheKeys;
        }
    };

    const verifyPromised = promisify(jsonwebtoken.verify.bind(jsonwebtoken));

    return async function (req, res, next) {
        try {
            const token = req.headers.authorization.split(" ")[1]
            const tokenSections = token.split('.');
            if (tokenSections.length < 2) {
                throw new Error('token is invalid');
            }
            const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
            const header = JSON.parse(headerJSON) as TokenHeader;
            const keys = await getPublicKeys();
            const key = keys[header.kid];
            if (key === undefined) {
                throw new Error('claim made for unknown kid');
            }
            const claim = await verifyPromised(token, key.pem) as Claim;
            const currentSeconds = Math.floor((new Date()).valueOf() / 1000);
            if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
                throw new Error('claim is expired or invalid');
            }
            if (claim.iss !== cognitoUrl) {
                throw new Error('claim issuer is invalid');
            }
            if (claim.token_use !== tokenType) {
                throw new Error('claim use is invalid');
            }
            if (!claim['cognito:groups'].some((group: string) => config.groups.includes(group))) {
                return ResponseBuilder.forbidden(res, 401, 'user is not in the authorized group');
            }
            next();
        } catch (error) {
            return ResponseBuilder.forbidden(res, 403, error);
        }

    }


}


export default Authenticate;
