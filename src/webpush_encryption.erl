%%
%% @doc Web Push Payload Encryption.
%%
%% Based on:
%%   https://developers.google.com/web/updates/2016/03/web-push-encryption and
%%   https://github.com/GoogleChrome/web-push-encryption.
%%

-module(webpush_encryption).

-define(AUTH_INFO, <<"Content-Encoding: auth", 0>>).

-type publicKey()  :: string()|binary().
-type authTokeny() :: string()|binary().
-type clientKey()  :: {publicKey(), authTokeny()}.
-type cryptData()  :: {binary(), binary(), binary()}.

-export_type([
	publicKey/0, 
	authTokeny/0, 
	clientKey/0, 
	cryptData/0
]).
-export([
	encrypt/3
]).


-spec encrypt(binary(), clientKey(), pos_integer() ) -> cryptData().
encrypt(Message, {ClientPublicKey, ClientAuthToken} = _ClientKey, PaddingLength) when 
	is_list(ClientPublicKey), is_list(ClientAuthToken) ->
	
	encrypt(Message, {base64url:decode(ClientPublicKey), base64url:decode(ClientAuthToken)}, PaddingLength);

encrypt(Message, {ClientPublicKey, ClientAuthToken} = _ClientKey, PaddingLength) ->
	Salt = crypto:strong_rand_bytes(16),
	ServerECDH = crypto:ec_curve(prime256v1),
	{PublicKey, PrivateKey} = crypto:generate_key(ecdh, prime256v1),
	SharedSecret = crypto:compute_key(ecdh, ClientPublicKey, PrivateKey, ServerECDH),
	Prk = hkdf(ClientAuthToken, SharedSecret, ?AUTH_INFO, 32),
	
	Context = context(ClientPublicKey, PublicKey),
	ContentEncryptionKeyInfo = info("aesgcm", Context),
	ContentEncryptionKey = hkdf(Salt, Prk, ContentEncryptionKeyInfo, 16),
	NonceInfo = info("nonce", Context),
	Nonce = hkdf(Salt, Prk, NonceInfo, 12),
	PaddingBuffer = create_padding(PaddingLength),

	Plaintext = <<PaddingBuffer/binary, Message/binary>>,
	Ciphertext = encrypt_payload(Plaintext, ContentEncryptionKey, Nonce),
	{Ciphertext, Salt, PublicKey}.

% private

hkdf(Salt, IKM, Info, Length) ->
	KeyHmac = crypto:hmac_init(sha256, Salt),
	KeyHmac = crypto:hmac_update(KeyHmac, IKM),
	Prk = crypto:hmac_final(KeyHmac),
	
	InfoHmac = crypto:hmac_init(sha256, Prk),
	InfoHmac = crypto:hmac_update(InfoHmac, Info),
	InfoHmac = crypto:hmac_update(InfoHmac, <<1>>),
	binary:part(crypto:hmac_final(InfoHmac), {0, Length}).


context(ClientPublicKey, PublicKey) ->
	<<0, (byte_size(ClientPublicKey)):16/big-unsigned-integer, ClientPublicKey/binary, (byte_size(PublicKey)):16/big-unsigned-integer, PublicKey/binary>>.

info(Type, Context) when is_list(Type) ->
	info(list_to_binary(Type), Context);
	
info(Type, Context) ->
	<<"Content-Encoding: ", Type/binary, 0, "P-256", Context/binary>>.
	
encrypt_payload(Plaintext, ContentEncryptionKey, Nonce) ->
	{CipherText, CipherTag} = crypto:block_encrypt(aes_gcm, ContentEncryptionKey, Nonce, {"", Plaintext}),
	<<CipherText/binary, CipherTag/binary>>.


create_padding(PaddingLength) ->
	Length = <<PaddingLength:16/big-unsigned-integer>>,
	<<Length/binary, (binary:copy(<<0>>, PaddingLength))/binary>>.