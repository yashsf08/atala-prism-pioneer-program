package getRevocationTime

import io.iohk.atala.prism.api.node.NodeAuthApiImpl
import io.iohk.atala.prism.credentials.CredentialBatchId
import io.iohk.atala.prism.crypto.Sha256Digest
import io.iohk.atala.prism.protos.GrpcOptions
import kotlinx.coroutines.runBlocking

val environment = "ppp.atalaprism.io"
val grpcOptions = GrpcOptions("https", environment, 50053)
val nodeAuthApi = NodeAuthApiImpl(GrpcOptions("https", environment, 50053))

fun main(args: Array<String>) {
    val batchId = try { CredentialBatchId.fromString(args[0])!! } catch (e: Exception) {throw Exception("expected batch id as first argument")}
    val credentialHash = try { Sha256Digest.fromHex(args[1]) } catch (e: Exception) {throw Exception("expected credential hash as second argument")}

    val result = runBlocking {
            nodeAuthApi.getCredentialRevocationTime(
                    batchId.id,
                    credentialHash)
        }

    println(result)
}

// Waits until an operation is confirmed by the Cardano network.
// NOTE: Confirmation doesn't necessarily mean that operation was applied. 
// For example, it could be rejected because of an incorrect signature or other reasons.
fun waitUntilConfirmed(nodePublicApi: NodePublicApi, operationId: AtalaOperationId) {
    var status = runBlocking {
        nodePublicApi.getOperationStatus(operationId)
    }
    while (status != AtalaOperationStatus.CONFIRMED_AND_APPLIED &&
        status != AtalaOperationStatus.CONFIRMED_AND_REJECTED
    ) {
        println("Current operation status: ${AtalaOperationStatus.asString(status)}")
        Thread.sleep(1000)
        status = runBlocking {
            nodePublicApi.getOperationStatus(operationId)
        }
    }
}

// Creates a list of potentially useful keys out of a mnemonic code
fun prepareKeysFromMnemonic(mnemonic: MnemonicCode, pass: String): Map<String, ECKeyPair> {
    val seed = KeyDerivation.binarySeed(mnemonic, pass)
    val issuerMasterKeyPair = KeyGenerator.deriveKeyFromFullPath(seed, 0, MasterKeyUsage, 0)
    val issuerIssuingKeyPair = KeyGenerator.deriveKeyFromFullPath(seed, 0, IssuingKeyUsage, 0)
    val issuerRevocationKeyPair = KeyGenerator.deriveKeyFromFullPath(seed, 0, RevocationKeyUsage, 0)
    return mapOf(
        Pair(PrismDid.DEFAULT_MASTER_KEY_ID, issuerMasterKeyPair),
        Pair(PrismDid.DEFAULT_ISSUING_KEY_ID, issuerIssuingKeyPair),
        Pair(PrismDid.DEFAULT_REVOCATION_KEY_ID, issuerRevocationKeyPair)
    )
}
