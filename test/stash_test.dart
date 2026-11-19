import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:openmls/openmls.dart';
import 'package:test/test.dart';

import 'test_helpers.dart';

void main() {
  late Directory dir;
  late Uint8List bobKey;
  late MlsEngine alice;
  late MlsEngine bob;
  late TestIdentity aliceId;
  late TestIdentity bobId;
  late Uint8List groupId;

  setUpAll(() async {
    await Openmls.init();
  });

  String bobPath() => '${dir.path}/bob.db';

  Future<Uint8List> send(String text) async => (await alice.createMessage(
    groupIdBytes: groupId,
    signerBytes: aliceId.signerBytes,
    message: Uint8List.fromList(utf8.encode(text)),
  )).ciphertext;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('openmls_stash_test');
    bobKey = testEncryptionKey();
    alice = await createTestEngine();
    bob = await MlsEngine.create(dbPath: bobPath(), encryptionKey: bobKey);
    aliceId = TestIdentity.create('alice');
    bobId = TestIdentity.create('bob');

    groupId = (await alice.createGroup(
      config: defaultConfig(),
      signerBytes: aliceId.signerBytes,
      credentialIdentity: aliceId.credentialIdentity,
      signerPublicKey: aliceId.publicKey,
    )).groupId;
    final bobKp = await bob.createKeyPackage(
      ciphersuite: ciphersuite,
      signerBytes: bobId.signerBytes,
      credentialIdentity: bobId.credentialIdentity,
      signerPublicKey: bobId.publicKey,
    );
    final added = await alice.addMembers(
      groupIdBytes: groupId,
      signerBytes: aliceId.signerBytes,
      keyPackagesBytes: [bobKp.keyPackageBytes],
    );
    await alice.mergePendingCommit(groupIdBytes: groupId);
    await bob.joinGroupFromWelcome(
      config: defaultConfig(),
      welcomeBytes: added.welcome,
      signerBytes: bobId.signerBytes,
    );
  });

  tearDown(() async {
    await bob.close();
    await dir.delete(recursive: true);
  });

  test('an application message is stashed until deleted', () async {
    final result = await bob.processMessageStashed(
      groupIdBytes: groupId,
      messageBytes: await send('hi'),
      stashId: 'a',
    );
    expect(utf8.decode(result.applicationMessage!), 'hi');

    final stashed = await bob.stashedMessages();
    expect(stashed.map((m) => m.stashId), ['a']);
    expect(stashed.single.groupId, groupId);
    expect(
      MlsCredential.deserialize(
        bytes: stashed.single.senderCredential,
      ).identity(),
      aliceId.credentialIdentity,
    );
    expect(utf8.decode(stashed.single.plaintext), 'hi');
    expect(await bob.stashedMessage(stashId: 'b'), isNull);

    await bob.deleteStashedMessage(stashId: 'a');
    expect(await bob.stashedMessages(), isEmpty);
    expect(await bob.stashedMessage(stashId: 'a'), isNull);
  });

  test('the stash outlives the key it was decrypted with', () async {
    final message = await send('kept');
    await bob.processMessageStashed(
      groupIdBytes: groupId,
      messageBytes: message,
      stashId: 'a',
    );

    // e.g. the process ended before the application stored the message
    await bob.close();
    bob = await MlsEngine.create(dbPath: bobPath(), encryptionKey: bobKey);

    await expectLater(
      bob.processMessage(groupIdBytes: groupId, messageBytes: message),
      throwsA(anything),
    );
    final stashed = await bob.stashedMessage(stashId: 'a');
    expect(utf8.decode(stashed!.plaintext), 'kept');
  });

  test('a stash id that is taken changes nothing', () async {
    await bob.processMessageStashed(
      groupIdBytes: groupId,
      messageBytes: await send('first'),
      stashId: 'a',
    );
    final second = await send('second');
    await expectLater(
      bob.processMessageStashed(
        groupIdBytes: groupId,
        messageBytes: second,
        stashId: 'a',
      ),
      throwsA(anything),
    );

    // the ratchet did not move, the message can still be read
    final result = await bob.processMessageStashed(
      groupIdBytes: groupId,
      messageBytes: second,
      stashId: 'b',
    );
    expect(utf8.decode(result.applicationMessage!), 'second');
    expect(
      utf8.decode((await bob.stashedMessage(stashId: 'a'))!.plaintext),
      'first',
    );
  });

  test('a commit is applied with nothing stashed', () async {
    final commit = await alice.selfUpdate(
      groupIdBytes: groupId,
      signerBytes: aliceId.signerBytes,
    );
    await alice.mergePendingCommit(groupIdBytes: groupId);

    final result = await bob.processMessageStashed(
      groupIdBytes: groupId,
      messageBytes: commit.commit,
      stashId: 'a',
    );
    expect(result.messageType, ProcessedMessageType.stagedCommit);
    expect(await bob.stashedMessages(), isEmpty);
    expect(
      await bob.groupEpoch(groupIdBytes: groupId),
      await alice.groupEpoch(groupIdBytes: groupId),
    );
  });
}
