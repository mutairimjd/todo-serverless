import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
// import Axios from 'axios'
// import { Jwt } from '../../auth/Jwt'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
// const jwksUrl = process.env.JWT_URL
// const cert = await Axios.get(jwksUrl).promise()

const cert = `-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJHBQhjxt6d07WMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMTFmRldi05Nng3MGV3Ny5hdXRoMC5jb20wHhcNMjAwMTA5MTMyNDI3WhcNMzMw
OTE3MTMyNDI3WjAhMR8wHQYDVQQDExZkZXYtOTZ4NzBldzcuYXV0aDAuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvh/AZ5x7FYkyQSZgX6gZt3M1
idTcelCrv5V4EecEriHDh9FT4IZKkArDlaNsBLKeqCiwF4x+p1n089QDrrDDKI85
GIT27gJ+RZRD/j9iHXLezH4Y9BQ0S/xZDtBKczNIet/T8Ypyd3UN7P3xi83X47ki
lEPg/Yr9GhAJQwxYsn3aXK6hFxegIyHJ6kUodwlWGHD+mJPmZoy+bMHi/kC7ZtGT
WPFH46EtigjTmkwy5xrEzHhYSA2v7GEg/mVuU6saD/aefbkbq/vUMdpkI+MW9DHO
nxIDiT6/TusWmQov4U4Pvh0Zm3sZ5RMtEUm7Apu6qGig9RBzyNHwRIDE1wI/jQID
AQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQkVanvlcnBeFjAGbW1
N0EJeyekgTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBABKL1NjC
7SBi9MoNst3pCv77Ram2CKPGn6+pnYVqnV/d95zKv+IeU5aszOA0boTq4QV4l/Xi
hEqcdC50l7y2v2y9uLlBZHNF1xGortp1LgJTwC8Yhsf58h+bIEcm9HYZYuAErQ6k
+oIDCdegroHAL09zLoVP5hL0OOyqPCIqnvbI6b/6gHDmO3D6XGEZcz9t8+joQg/r
6KF0Z8sPFH1Aa4TEkyKl6D69q6GBOSVeiqc3MqoKkdHWkDpdC+yRBo2vJI3jjlMS
v2UAzRRE7Vowu30vLlUCZnzd0c6E5CCtralRT//Am00ghGYI9HRNa2zP6o24MOQs
rE1p4QH1NV66j+s=
-----END CERTIFICATE-----`

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)
  // const jwt: Jwt = decode(token, { complete: true }) as Jwt

  // TODO: Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  return verify(token, cert, {algorithms: ['RS256']} ) as JwtPayload
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
