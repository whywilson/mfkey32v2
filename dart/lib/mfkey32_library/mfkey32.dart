import 'dart:async';
import 'dart:core';
import 'dart:ffi';
import 'dart:ffi' as ffi;
import 'dart:io' as io;
import 'dart:io';
import 'dart:isolate';

import 'package:dylib/dylib.dart';
import 'package:ffi/ffi.dart';

import 'bindings.dart';

class Mfkey32Nonce {
  int uid;
  int nt0;
  int nt1;
  int nr0Enc;
  int ar0Enc;
  int nr1Enc;
  int ar1Enc;

  Mfkey32Nonce({required this.uid,
    required this.nt0,
    required this.nt1,
    required this.nr0Enc,
    required this.ar0Enc,
    required this.nr1Enc,
    required this.ar1Enc});
}

class Mfkey32Item {
  String uid;
  int block;
  String key;

  Mfkey32Item({required this.uid, required this.block, required this.key});
}

Future<List<int>> mfkey32(Mfkey32Nonce mfkey) async {
  final SendPort helperIsolateSendPort = await _helperIsolateSendPort;
  final int requestId = _nextSumRequestId++;
  final Mfkey32Request request = Mfkey32Request(requestId, mfkey);
  final Completer<List<int>> completer = Completer<List<int>>();
  requests[requestId] = completer;
  helperIsolateSendPort.send(request);
  return completer.future;
}

String resolvePath() {
  if (Platform.isMacOS || Platform.isIOS) {
    return '$_libName.framework/$_libName';
  } else if (Platform.isAndroid || Platform.isLinux) {
    return 'lib$_libName.so';
  }
  String path = resolveDylibPath(
    'mfkey32_library',
    dartDefine: 'LIBRECOVERY_PATH',
    environmentVariable: 'LIBRECOVERY_PATH',
  );
  return path;
}

const String _libName = 'mfkey32_library';

final Mfkey32_Library _bindings = Mfkey32_Library(DynamicLibrary.open(resolvePath()));

class Mfkey32Request {
  final int id;
  final Mfkey32Nonce mfkey32;

  Mfkey32Request(this.id, this.mfkey32);
}

/// A response with the result of `sum`.
///
/// Typically sent from one isolate to another.
class KeyResponse {
  final int id;
  final List<int> result;

  const KeyResponse(this.id, this.result);
}

/// Counter to identify requests and [Response]s.
int _nextSumRequestId = 0;

/// Mapping from request `id`s to the completers corresponding to the correct future of the pending request.
final Map<int, Completer<List<int>>> requests = <int, Completer<List<int>>>{};

/// The SendPort belonging to the helper isolate.
Future<SendPort> _helperIsolateSendPort = () async {
  // The helper isolate is going to send us back a SendPort, which we want to
  // wait for.
  final Completer<SendPort> completer = Completer<SendPort>();

  // Receive port on the main isolate to receive messages from the helper.
  // We receive two types of messages:
  // 1. A port to send messages on.
  // 2. Responses to requests we sent.
  final ReceivePort receivePort = ReceivePort()
    ..listen((dynamic data) {
      if (data is SendPort) {
        // The helper isolate sent us the port on which we can sent it requests.
        completer.complete(data);
        return;
      }
      if (data is KeyResponse) {
        // The helper isolate sent us a response to a request we sent.
        final Completer<List<int>> completer = requests[data.id]!;
        requests.remove(data.id);
        completer.complete(data.result);
        return;
      }
      throw UnsupportedError('Unsupported message type: ${data.runtimeType}');
    });

  await Isolate.spawn((SendPort sendPort) async {
    final ReceivePort helperReceivePort = ReceivePort()
      ..listen((dynamic data) {
        // On the helper isolate listen to requests and respond to them.
        if (data is Mfkey32Request) {
          Pointer<Mfkey32> pointer = calloc();
          pointer.ref.uid = data.mfkey32.uid;
          pointer.ref.nt0 = data.mfkey32.nt0;
          pointer.ref.nt1 = data.mfkey32.nt1;
          pointer.ref.nr0_enc = data.mfkey32.nr0Enc;
          pointer.ref.ar0_enc = data.mfkey32.ar0Enc;
          pointer.ref.nr1_enc = data.mfkey32.nr1Enc;
          pointer.ref.ar1_enc = data.mfkey32.ar1Enc;

          final int result = _bindings.mfkey32(pointer);
          final KeyResponse response = KeyResponse(data.id, [result]);
          sendPort.send(response);
          return;
        }
        throw UnsupportedError('Unsupported message type: ${data.runtimeType}');
      });

    // Send the port to the main isolate on which we can receive requests.
    sendPort.send(helperReceivePort.sendPort);
  }, receivePort.sendPort);

  // Wait until the helper isolate has sent us back the SendPort on which we
  // can start sending requests.
  return completer.future;
}();
