package getDidDocument

import io.iohk.atala.prism.api.*
import io.iohk.atala.prism.api.models.AtalaOperationId
import io.iohk.atala.prism.api.models.AtalaOperationStatus
import io.iohk.atala.prism.api.node.*
import io.iohk.atala.prism.common.PrismSdkInternal
import io.iohk.atala.prism.crypto.Sha256Digest
import io.iohk.atala.prism.crypto.derivation.KeyDerivation
import io.iohk.atala.prism.crypto.derivation.MnemonicCode
import io.iohk.atala.prism.crypto.keys.ECKeyPair
import io.iohk.atala.prism.identity.*
import io.iohk.atala.prism.protos.*
import kotlinx.coroutines.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import pbandk.ByteArr
import java.io.File

val environment = "ppp.atalaprism.io"
val grpcOptions = GrpcOptions("https", environment, 50053)
val nodeAuthApi = NodeAuthApiImpl(GrpcOptions("https", environment, 50053))

@PrismSdkInternal
fun main(args: Array<String>) {
    if (args.size != 1) {
        throw Exception("expected exactly one command line argument, the DID")
    }

    val did = try { Did.fromString(args[0]) } catch (e: Exception) { throw Exception("illegal DID: ${args[0]}") }
    val prismDid = try { PrismDid.fromDid(did) } catch (e: Exception) { throw Exception("not a Prism DID: $did") }

    println("trying to retrieve document for $did")
    try {
        val model = runBlocking { nodeAuthApi.getDidDocument(prismDid) }
        println(model.didDataModel)
        for (info in model.publicKeys) {
            println()
            println(info)
        }
        println()
    } catch (e: Exception) {
        println("unknown prism DID")
    }
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
