import org.bitcoinj.core.ECKey;
import org.bitcoinj.params.TestNet3Params;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws Exception {

        //TESTS

        String myLegacy = "70736274ff0100550200000001bcb6bdf6b8ddfbc0f47e445588fc5be1a4d3252c153917161dfc7159b537121b0000000000fdffffff0115c20000000000001976a914eb8a0e37824a4d3ce32a3795eceb7811dfbc856c88ac304d22004f01043587cf035b3e59ba80000000e1eb03a68ea5d8c51d5807c64f867848e77fc187485b7decd2dd1c44f38a1e8602130a2ea8a1411d00725444e482258703aae3a445362ca4862317f90998bc4b2610000000003100008001000080000000800001006c0200000001fb6ccee6bdc232ebf955cf322712d158fee1dba7c91b164400b64cc194a6e7610000000017160014535146a98ec54db5d9751415e41c135164f66206ffffffff0116c20000000000001976a9140d67958e3d6404d7a5bdea1c3c5f88c54e85996a88ac0000000001030401000000220602414469f58cda44a285963ac5c387d907c27bc56621cf1184bfc35c74b58e626c18000000002c0000800000008000000080000000000400000000220202073b1f1714bcdaf3da6518c5563fbc5889d676a5112b7cba5bd5cf10d71acdc518000000002c0000800000008000000080000000000500000000";
        String sparrowLegacy = "70736274ff0100550200000001bcb6bdf6b8ddfbc0f47e445588fc5be1a4d3252c153917161dfc7159b537121b0000000000fdffffff0115c20000000000001976a914eb8a0e37824a4d3ce32a3795eceb7811dfbc856c88ac304d22004f01043587cf035b3e59ba80000000e1eb03a68ea5d8c51d5807c64f867848e77fc187485b7decd2dd1c44f38a1e8602130a2ea8a1411d00725444e482258703aae3a445362ca4862317f90998bc4b2610000000002c00008000000080000000000001006c0200000001fb6ccee6bdc232ebf955cf322712d158fee1dba7c91b164400b64cc194a6e7610000000017160014535146a98ec54db5d9751415e41c135164f66206ffffffff0116c20000000000001976a9140d67958e3d6404d7a5bdea1c3c5f88c54e85996a88ac0000000001030401000000220602414469f58cda44a285963ac5c387d907c27bc56621cf1184bfc35c74b58e626c18000000002c0000800000008000000000000000000400000000220202073b1f1714bcdaf3da6518c5563fbc5889d676a5112b7cba5bd5cf10d71acdc518000000002c0000800000008000000000000000000500000000";

        String myCompat = "70736274ff01007c0200000002a4373954617572ff7e2dd93397df266156f14f82cb55f054c7df73f753f10e730000000000fdffffffa4373954617572ff7e2dd93397df266156f14f82cb55f054c7df73f753f10e730100000000fdffffff01e7af02000000000017a914d4134e65e4aa0600493e99163e270e2047ea130a87da6522004f01043587cf039f4d230c80000000183901ebd4ad87386cba6bb6fefab51d3621965d2578eb05b72aa391fb94e85f032e034599e5610dad1f43fd8ad34956c689da0bf7d5982f1eb976a601e8a56924101fe613363100008001000080000000800001008a0200000001046353dcb7b58eccdd5fef1753ceb5656a20682224342302994f4d022dc2f41a0000000017160014b1e865611857028bd723cedba5cedd0a3e22cc4afdffffff02803801000000000017a9147d3928df049a17ef11eaf0a6c7172c137b154ca887487801000000000017a914a130db58c5cfde47f1bdc61b82a43a0c9b0381278739f82100010120803801000000000017a9147d3928df049a17ef11eaf0a6c7172c137b154ca887010304010000000104160014ece2429798b4ab644df5c7b971066cc9a11b31c8220603af8c2da87a89c94f7aa732ec5f26cd0f161b82ab33f6fc641ee93ca0341f7f84181fe6133631000080010000800000008000000000010000000001008a0200000001046353dcb7b58eccdd5fef1753ceb5656a20682224342302994f4d022dc2f41a0000000017160014b1e865611857028bd723cedba5cedd0a3e22cc4afdffffff02803801000000000017a9147d3928df049a17ef11eaf0a6c7172c137b154ca887487801000000000017a914a130db58c5cfde47f1bdc61b82a43a0c9b0381278739f82100010120487801000000000017a914a130db58c5cfde47f1bdc61b82a43a0c9b03812787010304010000000104160014b58186f855e680b2f54c7d493e18e95f0b40b2442206031896542bebf66ccb38b841988dfb2e0ab640c87ab0f2ae9a40dc675b4b286cd8181fe613363100008001000080000000800100000000000000000100160014982ed864d74e3c6fb03c188d99875129bb253dfd220203fe2f409cc4536f6c79d6d61e4a7135858fea122d99e71ded0e913d68722739d2181fe61336310000800100008000000080000000000200000000";
        String sparrowCompat = "70736274ff01007c0200000002a4373954617572ff7e2dd93397df266156f14f82cb55f054c7df73f753f10e730000000000fdffffffa4373954617572ff7e2dd93397df266156f14f82cb55f054c7df73f753f10e730100000000fdffffff01e7af02000000000017a914d4134e65e4aa0600493e99163e270e2047ea130a87da6522004f01043587cf039f4d230c80000000183901ebd4ad87386cba6bb6fefab51d3621965d2578eb05b72aa391fb94e85f032e034599e5610dad1f43fd8ad34956c689da0bf7d5982f1eb976a601e8a56924101fe613363100008001000080000000800001008a0200000001046353dcb7b58eccdd5fef1753ceb5656a20682224342302994f4d022dc2f41a0000000017160014b1e865611857028bd723cedba5cedd0a3e22cc4afdffffff02803801000000000017a9147d3928df049a17ef11eaf0a6c7172c137b154ca887487801000000000017a914a130db58c5cfde47f1bdc61b82a43a0c9b0381278739f82100010120803801000000000017a9147d3928df049a17ef11eaf0a6c7172c137b154ca887010304010000000104160014ece2429798b4ab644df5c7b971066cc9a11b31c8220603af8c2da87a89c94f7aa732ec5f26cd0f161b82ab33f6fc641ee93ca0341f7f84181fe6133631000080010000800000008000000000010000000001008a0200000001046353dcb7b58eccdd5fef1753ceb5656a20682224342302994f4d022dc2f41a0000000017160014b1e865611857028bd723cedba5cedd0a3e22cc4afdffffff02803801000000000017a9147d3928df049a17ef11eaf0a6c7172c137b154ca887487801000000000017a914a130db58c5cfde47f1bdc61b82a43a0c9b0381278739f82100010120487801000000000017a914a130db58c5cfde47f1bdc61b82a43a0c9b03812787010304010000000104160014b58186f855e680b2f54c7d493e18e95f0b40b2442206031896542bebf66ccb38b841988dfb2e0ab640c87ab0f2ae9a40dc675b4b286cd8181fe613363100008001000080000000800100000000000000000100160014982ed864d74e3c6fb03c188d99875129bb253dfd220203fe2f409cc4536f6c79d6d61e4a7135858fea122d99e71ded0e913d68722739d2181fe61336310000800100008000000080000000000200000000";

        String myTaproot = "70736274ff01005e0200000001146935b57b36d17cdbbdb3c412f72244ac25614b2a7b9dc370b61088f5a811c501000000000000000001308601000000000022512080e2d9c811ad041953e25524bf7eb3cd6541b7bc3804b83eeb44ac49da3aef15000000004f01043587cf03be997f388000000051dd0cc3bdc3ab2f5f0397b6e7ea2df9c2b8cfaade859ae431d795b33db00f9c03ed10791895a6ecc155dd969b78b212b9f31e42a11eca37a167edf54638360ef9103927daee3100008001000080000000800001007d0200000001056e30a45ffd7b0e5ec724ebd4f67583eb1a38688b32b2b31cbb00430fc2556a0000000000feffffff0244366a6e000000001600145791c4c80ec1cdc287643b2b683d4493f35a96cba0860100000000002251206b5cbd16adef9c4ea9b0ae02d75e12cce463509ac1af48d17958995f1a0082e3a767220001012ba0860100000000001651205e6861ac2a08ee1e7b7e57379478caef2b4227175359e8bd3df090118e1619c0010304000000002206025e6861ac2a08ee1e7b7e57379478caef2b4227175359e8bd3df090118e1619c0183927daee560000800100008000000080000000000000000021165e6861ac2a08ee1e7b7e57379478caef2b4227175359e8bd3df090118e1619c019003927daee56000080010000800000008000000000000000000117205e6861ac2a08ee1e7b7e57379478caef2b4227175359e8bd3df090118e1619c0002202023762943fa4da61f1c291331e9f6f71e5246b2fa0f0f55e2be69452b0601c97c2183927daee560000800000008000000080000000000100000000";
        String sparrowTaproot = "70736274ff01005e0200000001146935b57b36d17cdbbdb3c412f72244ac25614b2a7b9dc370b61088f5a811c501000000000000000001308601000000000022512080e2d9c811ad041953e25524bf7eb3cd6541b7bc3804b83eeb44ac49da3aef15000000004f01043587cf03be997f388000000051dd0cc3bdc3ab2f5f0397b6e7ea2df9c2b8cfaade859ae431d795b33db00f9c03ed10791895a6ecc155dd969b78b212b9f31e42a11eca37a167edf54638360ef9103927daee5600008001000080000000800001007d0200000001056e30a45ffd7b0e5ec724ebd4f67583eb1a38688b32b2b31cbb00430fc2556a0000000000feffffff0244366a6e000000001600145791c4c80ec1cdc287643b2b683d4493f35a96cba0860100000000002251206b5cbd16adef9c4ea9b0ae02d75e12cce463509ac1af48d17958995f1a0082e3a767220001012ba0860100000000002251206b5cbd16adef9c4ea9b0ae02d75e12cce463509ac1af48d17958995f1a0082e3010304000000002206036b5cbd16adef9c4ea9b0ae02d75e12cce463509ac1af48d17958995f1a0082e3183927daee560000800100008000000080000000000000000021165e6861ac2a08ee1e7b7e57379478caef2b4227175359e8bd3df090118e1619c019003927daee56000080010000800000008000000000000000000117205e6861ac2a08ee1e7b7e57379478caef2b4227175359e8bd3df090118e1619c0002202023762943fa4da61f1c291331e9f6f71e5246b2fa0f0f55e2be69452b0601c97c2183927daee560000800100008000000080000000000100000000";


        PSBT.setDebug(true);
        PSBT psbt = PSBT.fromBytes(Hex.decode(myLegacy.replaceAll(" ", "")));
        PSBT.setDebug(false);

        System.out.println("SEMOLA ===================== SEMOLA ================ SEMOLA ");
        PSBT.setDebug(true);
        PSBT psbt1 = PSBT.fromBytes(Hex.decode(sparrowLegacy.replaceAll(" ", "")));
        PSBT.setDebug(false);

        //psbt.addInputTaproot(TestNet3Params.get(), Hex.decode("0d8c85ab"), eckeyInput0, 175000000L, 84, 1, 0, 0, 8, "0200000001056e30a45ffd7b0e5ec724ebd4f67583eb1a38688b32b2b31cbb00430fc2556a0000000000feffffff0244366a6e000000001600145791c4c80ec1cdc287643b2b683d4493f35a96cba0860100000000002251206b5cbd16adef9c4ea9b0ae02d75e12cce463509ac1af48d17958995f1a0082e3a7672200");

    }
}
