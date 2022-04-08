package createDid

import io.iohk.atala.prism.api.KeyGenerator
import io.iohk.atala.prism.common.PrismSdkInternal
import io.iohk.atala.prism.crypto.derivation.KeyDerivation
import io.iohk.atala.prism.identity.PrismDid
import io.iohk.atala.prism.identity.PrismKeyType
import java.io.File

@PrismSdkInternal
fun main(args: Array<String>) {
    val seedFile = try { args[0] } catch (e: Exception) {throw Exception("expected seed file path as argument")}
    val seed = KeyDerivation.binarySeed(KeyDerivation.randomMnemonicCode(), "passphrase")
    File(seedFile).writeBytes(seed)
    println("wrote seed to file $seedFile")
    println()

    val masterKeyPair = KeyGenerator.deriveKeyFromFullPath(seed, 0, MasterKeyUsage, 0)
    val unpublishedDid = PrismDid.buildLongFormFromMasterPublicKey(masterKeyPair.publicKey)

    val didCanonical = unpublishedDid.asCanonical().did
    val didLongForm = unpublishedDid.did

    println("canonical: $didCanonical")
    println("long form: $didLongForm")
    println()
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