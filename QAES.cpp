#include "QAES.h"
/*
 *  -*- QAES Lock File Format -*-
 *  This is not designed for secure encryption
 *  This is just to isolate malware.
 * 
 *  Locked File Layer Format
 *
 *             +-------------------------------+
 *  AES128 Key |0 1 2 3 4 5 6 7 8 9 A B C D E F|
 *             +-------------------------------+
 *             +-------------------------------+
 *  AES128 IV  |0 1 2 3 4 5 6 7 8 9 A B C D E F|
 *             +-------------------------------+
 *             +-------------------------------+
 *  AES128     |0 1 2 3 4 5 6 7 8 9 A B C D E F|
 *  CIPHERTEXT |0 1 2 3 4 5 6 7 8 9 A B C D E F|
 *             |0 1 2 3 4 5 6 7 8 9 A B C D E F|
 *              ...
 *             +-------------------------------+
 *             
 *  Unlocked Inner Layer Format
 *    +-----------------------------------------------------------------+
 *  0 | 'A' 'E' 'S' '_' '1' '2' '8' '_' 'C' 'B' 'C' '_'| 4-Octet CRC32  |
 *    |  0   1   2   3   4   5   6   7   8   9   A   B | C   D   E   F  |
 *    +-----------------------------------------------------------------+
 *    +-----------------------------------------------------------------+
 *  1 | 4-Octet Time   |        8-Octet Filesize       | 4-Octet NameLen|
 *    |  0   1   2   3 | 4   5   6   7   8   9   A   B | C   D   E   F  |
 *    +-----------------------------------------------------------------+
 *  2+  NameLen-Octets for Filename | Filesize-Octets for File Contents
 */

QAES::QAES(){
    init_const();
}

QAES::~QAES(){

}

QByteArray QAES::encrypt(const QByteArray filename, const QByteArray buffer, const QByteArray key, const QByteArray iv, const quint32 *timestamp){
    if(key.length() != 16 || iv.length() != 16 || buffer.length() == 0)
        return QByteArray();
    QByteArray working_iv = iv;
    QByteArray working_buffer;
    if(!headerAES128CBC(&working_buffer, filename, buffer, timestamp))
        return QByteArray();
    QByteArray round_key = key_expansion(key);
    QByteArray ret = QByteArray();
    QByteArray state;
    quint64 pos = 0;
    while(pos < (quint64)working_buffer.length()){
        quint8 round = 0;
        state = working_buffer.mid(pos, 16);
        while(state.length() < 16)
            state.append(QByteArray(1,11));
        state = xor_bytes(state, working_iv);
        state = add_round_key(state, round, round_key);
        for(round = 1; round < 11; round++){
            state = substitute_bytes(state);
            state = shift_rows(state);
            if(round!=10)
                state = mix_columns(state);
            state = add_round_key(state, round, round_key);
        }
        working_iv = state;

        ret.append(state);
        pos += 16;
    }
    return ret;
}

QByteArray QAES::decrypt(const QByteArray buffer, const QByteArray key, const QByteArray iv, QByteArray *filename, quint32 *timestamp, quint64 *file_size){
    (*filename) = QByteArray();
    if(key.length() != 16 || iv.length() != 16 || buffer.length() < 48 || (buffer.length() % 16) != 0 )
        return QByteArray();
    QByteArray working_iv = iv;
    QByteArray round_key = key_expansion(key);
    QByteArray state;

    QByteArray ret = QByteArray();
    quint64 pos = 0;

    while(pos < (quint64)buffer.length()){
        qint8 round = 10;
        state = buffer.mid(pos,16);
        state = add_round_key(state, round, round_key);
        for(round = 9; round >= 0; round--){
            state = inverse_shift_rows(state);
            state = inverse_substitute_bytes(state);
            state = add_round_key(state, round, round_key);
            if(round)
                state = inverse_mix_columns(state);
        }
        state = xor_bytes(state, working_iv);
        working_iv = buffer.mid(pos,16);
        ret.append(state);
        pos += 16;
    }
    if(ret.length() < 48)
        return QByteArray();
    if(QByteArray("AES_128_CBC_", 12)!=ret.mid(0,12))
        return QByteArray();
    ret.remove(0,12);
    quint32 crc = (ret.at(3)&0xff) + ((ret.at(2)&0xff) << 8) + ((ret.at(1)&0xff) << 16) + ((ret.at(0)&0xff) << 24);
    ret.remove(0,4);
    if(timestamp != Q_NULLPTR)
        (*timestamp) = (ret.at(3)&0xff) + ((ret.at(2)&0xff) << 8) + ((ret.at(1)&0xff) << 16) + ((ret.at(0)&0xff) << 24);
    ret.remove(0,4);
    quint64 size = (ret.at(7)&0xff) + ((ret.at(6)&0xff) << 8) + ((ret.at(5)&0xff) << 16) +
            ((ret.at(4)&0xff) << 24) + (((quint64)ret.at(3)&0xff) << 32) +
            (((quint64)ret.at(2)&0xff) << 40) + (((quint64)ret.at(1)&0xff) << 48) +
            (((quint64)ret.at(0)&0xff) << 56);
    ret.remove(0,8);
    if(size == 0)
        return QByteArray();
    quint64 namesize = (ret.at(3)&0xff) + ((ret.at(2)&0xff) << 8) + ((ret.at(1)&0xff) << 16) +
            ((ret.at(0)&0xff) << 24);
    ret.remove(0,4);
    if(namesize == 0 || (quint64)ret.length() < namesize)
        return QByteArray();
    if(filename != Q_NULLPTR)
        (*filename) = ret.mid(0,namesize);
    ret.remove(0,namesize);
    if(size == 0 || (quint64)ret.length() < size){
        (*filename) = QByteArray();
        return QByteArray();
    }
    ret = ret.mid(0,size);
    quint32 test;
    crc32(ret, &test);
    if(crc != test)
        return QByteArray();
    if(file_size != Q_NULLPTR)
        (*file_size) = ret.length();
    return ret;
}

QByteArray QAES::lock(const QByteArray filename, const QByteArray buffer, const quint32 *timestamp){
    QByteArray key, iv;
#if QT_VERSION >= 0x050a00
    for(int i = 0; i < 4; i++){
        quint32 value = QRandomGenerator::global()->generate();
        key.append(value & 0xff);
        key.append((value & 0xff00) >> 8);
        key.append((value & 0xff0000) >> 16);
        key.append((value & 0xff000000) >> 24);
    }
    for(int i = 0; i < 4; i++){
        quint32 value = QRandomGenerator::global()->generate();
        iv.append(value & 0xff);
        iv.append((value & 0xff00) >> 8);
        iv.append((value & 0xff0000) >> 16);
        iv.append((value & 0xff000000) >> 24);
    }
#else
    for(int i = 0; i < 16; i++)
        key.append((quint8)(qrand()&0xff));
    for(int i = 0; i < 16; i++)
        iv.append((quint8)(qrand()&0xff));
#endif
    QByteArray ciphertext = encrypt(filename, buffer, key, iv, timestamp);
    if(ciphertext.length() < 32 || (ciphertext.length() % 16) != 0 || key.length() != 16 || iv.length() != 16)
        return QByteArray();
    return key+iv+ciphertext;
}

QByteArray QAES::unlock(const QByteArray buffer, QByteArray *filename, quint32 *timestamp, quint64 *file_size){
    if(buffer.length() < 64)
        return QByteArray();
    QByteArray key = buffer.mid(0,16);
    QByteArray iv = buffer.mid(16,16);
    return decrypt(buffer.mid(32), key, iv, filename, timestamp, file_size);
}

bool QAES::verify(const QByteArray buffer, QByteArray *filename, quint32 *timestamp, quint64 *file_size){
    return unlock(buffer, filename, timestamp, file_size).length() != 0;
}

QByteArray QAES::key_expansion(const QByteArray key){
    if(key.length() != 16)
        return QByteArray();
    QByteArray ret, a;
    quint8 i = 0, j = 0, k = 0;
    ret = key;
    for(i = 0; i < 40; i++){
        j = 4*i+12;
        for(k = 0; k < 4; k++)
            a[k] = ret.at(j + k);
        if(i % 4 == 0){
            uint8_t tmp = a[0];
            for(k = 0; k < 3; k++)
                a[k] = ret.at(k+1);
            a[3] = tmp;
            for(k = 0; k < 4; k++)
                a[k] = sbox.at((quint8)a.at(k));
            a[0] = a[0]^rcwa.at((i/4)+1);
        }
        j = 4*i;
        for(k = 0; k < 4; k++)
            ret.append(ret.at(j+k)^a.at(k));
    }
    return ret;
}

void QAES::init_const(){
    sbox = QByteArray("\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76"
                      "\xca\x82\xc9\x7d\xfa\x59\x47\xf0\xad\xd4\xa2\xaf\x9c\xa4\x72\xc0"
                      "\xb7\xfd\x93\x26\x36\x3f\xf7\xcc\x34\xa5\xe5\xf1\x71\xd8\x31\x15"
                      "\x04\xc7\x23\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\x27\xb2\x75"
                      "\x09\x83\x2c\x1a\x1b\x6e\x5a\xa0\x52\x3b\xd6\xb3\x29\xe3\x2f\x84"
                      "\x53\xd1\x00\xed\x20\xfc\xb1\x5b\x6a\xcb\xbe\x39\x4a\x4c\x58\xcf"
                      "\xd0\xef\xaa\xfb\x43\x4d\x33\x85\x45\xf9\x02\x7f\x50\x3c\x9f\xa8"
                      "\x51\xa3\x40\x8f\x92\x9d\x38\xf5\xbc\xb6\xda\x21\x10\xff\xf3\xd2"
                      "\xcd\x0c\x13\xec\x5f\x97\x44\x17\xc4\xa7\x7e\x3d\x64\x5d\x19\x73"
                      "\x60\x81\x4f\xdc\x22\x2a\x90\x88\x46\xee\xb8\x14\xde\x5e\x0b\xdb"
                      "\xe0\x32\x3a\x0a\x49\x06\x24\x5c\xc2\xd3\xac\x62\x91\x95\xe4\x79"
                      "\xe7\xc8\x37\x6d\x8d\xd5\x4e\xa9\x6c\x56\xf4\xea\x65\x7a\xae\x08"
                      "\xba\x78\x25\x2e\x1c\xa6\xb4\xc6\xe8\xdd\x74\x1f\x4b\xbd\x8b\x8a"
                      "\x70\x3e\xb5\x66\x48\x03\xf6\x0e\x61\x35\x57\xb9\x86\xc1\x1d\x9e"
                      "\xe1\xf8\x98\x11\x69\xd9\x8e\x94\x9b\x1e\x87\xe9\xce\x55\x28\xdf"
                      "\x8c\xa1\x89\x0d\xbf\xe6\x42\x68\x41\x99\x2d\x0f\xb0\x54\xbb\x16",256);
    rbox = QByteArray("\x52\x09\x6a\xd5\x30\x36\xa5\x38\xbf\x40\xa3\x9e\x81\xf3\xd7\xfb"
                      "\x7c\xe3\x39\x82\x9b\x2f\xff\x87\x34\x8e\x43\x44\xc4\xde\xe9\xcb"
                      "\x54\x7b\x94\x32\xa6\xc2\x23\x3d\xee\x4c\x95\x0b\x42\xfa\xc3\x4e"
                      "\x08\x2e\xa1\x66\x28\xd9\x24\xb2\x76\x5b\xa2\x49\x6d\x8b\xd1\x25"
                      "\x72\xf8\xf6\x64\x86\x68\x98\x16\xd4\xa4\x5c\xcc\x5d\x65\xb6\x92"
                      "\x6c\x70\x48\x50\xfd\xed\xb9\xda\x5e\x15\x46\x57\xa7\x8d\x9d\x84"
                      "\x90\xd8\xab\x00\x8c\xbc\xd3\x0a\xf7\xe4\x58\x05\xb8\xb3\x45\x06"
                      "\xd0\x2c\x1e\x8f\xca\x3f\x0f\x02\xc1\xaf\xbd\x03\x01\x13\x8a\x6b"
                      "\x3a\x91\x11\x41\x4f\x67\xdc\xea\x97\xf2\xcf\xce\xf0\xb4\xe6\x73"
                      "\x96\xac\x74\x22\xe7\xad\x35\x85\xe2\xf9\x37\xe8\x1c\x75\xdf\x6e"
                      "\x47\xf1\x1a\x71\x1d\x29\xc5\x89\x6f\xb7\x62\x0e\xaa\x18\xbe\x1b"
                      "\xfc\x56\x3e\x4b\xc6\xd2\x79\x20\x9a\xdb\xc0\xfe\x78\xcd\x5a\xf4"
                      "\x1f\xdd\xa8\x33\x88\x07\xc7\x31\xb1\x12\x10\x59\x27\x80\xec\x5f"
                      "\x60\x51\x7f\xa9\x19\xb5\x4a\x0d\x2d\xe5\x7a\x9f\x93\xc9\x9c\xef"
                      "\xa0\xe0\x3b\x4d\xae\x2a\xf5\xb0\xc8\xeb\xbb\x3c\x83\x53\x99\x61"
                      "\x17\x2b\x04\x7e\xba\x77\xd6\x26\xe1\x69\x14\x63\x55\x21\x0c\x7d",256);
    rcwa = QByteArray("\x8d\x01\x02\x04\x08\x10\x20\x40\x80\x1b\x36", 11);
    crc_table = QList<quint32>({
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
        0xe963a535, 0x9e6495a3,	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
        0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
        0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9,
        0xfa0f3d63, 0x8d080df5,	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
        0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,	0x35b5a8fa, 0x42b2986c,
        0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
        0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,	0x76dc4190, 0x01db7106,
        0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
        0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
        0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
        0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
        0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
        0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
        0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
        0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
        0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
        0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
        0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
        0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
        0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
        0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
        0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
        0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
        0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
        0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
        0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
        0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
        0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
    });
}

QByteArray QAES::xor_bytes(const QByteArray in1, const QByteArray in2){
    QByteArray ret;
    quint64 max_length = in1.length() ^ ((in1.length() ^ in2.length()) & -(in1.length() < in2.length()));
    for(quint64 i = 0; i < max_length; i++)
        ret.insert(i, in1.at(i) ^ in2.at(i));
    return ret;
}

QByteArray QAES::add_round_key(const QByteArray state, const quint8 round_num, const QByteArray round_key){
    QByteArray ret;
    for (quint8 i = 0; i < 16; ++i){
        ret.append(state.at(i)^(round_key.at(16*round_num + i)));
    }
    return ret;
}

QByteArray QAES::substitute_bytes(const QByteArray state){
    QByteArray ret;
    for (quint8 i = 0; i < 16; ++i)
        ret.append((quint8)sbox.at((quint8)state.at(i)));
    return ret;
}

QByteArray QAES::shift_rows(const QByteArray state){
    QByteArray ret;
    ret.append(state.at(0));  // 0
    ret.append(state.at(5));  // 1
    ret.append(state.at(10)); // 2
    ret.append(state.at(15)); // 3
    ret.append(state.at(4));  // 4
    ret.append(state.at(9));  // 5
    ret.append(state.at(14)); // 6
    ret.append(state.at(3));  // 7
    ret.append(state.at(8));  // 8
    ret.append(state.at(13)); // 9
    ret.append(state.at(2));  //10
    ret.append(state.at(7));  //11
    ret.append(state.at(12)); //12
    ret.append(state.at(1));  //13
    ret.append(state.at(6));  //14
    ret.append(state.at(11)); //15
    return ret;
}

quint8 QAES::xfer(const quint8 in){
    return (0x1b*((in>>7)&1))^(in<<1);
}

QByteArray QAES::mix_columns(const QByteArray state){
    QByteArray ret;
    for(quint8 i = 0; i < 4; i++){
        quint8 tmp1 = state.at(4*i);
        quint8 tmp2 = tmp1^state.at(4*i+1)^state.at(4*i+2)^state.at(4*i+3);
        ret.append(state.at(4*i)^xfer(state.at(4*i)^state.at(4*i+1))^tmp2);
        ret.append(state.at(4*i+1)^xfer(state.at(4*i+1)^state.at(4*i+2))^tmp2);
        ret.append(state.at(4*i+2)^xfer(state.at(4*i+2)^state.at(4*i+3))^tmp2);
        ret.append(state.at(4*i+3)^xfer(state.at(4*i+3)^tmp1)^tmp2);
    }
    return ret;
}

QByteArray QAES::inverse_substitute_bytes(const QByteArray state){
    QByteArray ret;
    for (quint8 i = 0; i < 16; ++i)
        ret.append((quint8)rbox.at((quint8)state.at(i)));
    return ret;
}

QByteArray QAES::inverse_shift_rows(const QByteArray state){
    QByteArray ret;
    ret.append(state.at(0));  // 0
    ret.append(state.at(13)); // 1
    ret.append(state.at(10)); // 2
    ret.append(state.at(7));  // 3
    ret.append(state.at(4));  // 4
    ret.append(state.at(1));  // 5
    ret.append(state.at(14)); // 6
    ret.append(state.at(11)); // 7
    ret.append(state.at(8));  // 8
    ret.append(state.at(5));  // 9
    ret.append(state.at(2));  //10
    ret.append(state.at(15)); //11
    ret.append(state.at(12)); //12
    ret.append(state.at(9));  //13
    ret.append(state.at(6));  //14
    ret.append(state.at(3));  //15
    return ret;
}

QByteArray QAES::inverse_mix_columns(const QByteArray state){
    QByteArray ret;
    for(quint8 i = 0; i < 4; i++){
        quint8 tmp0 = state.at(4*i), tmp1 = state.at(4*i+1), tmp2 = state.at(4*i+2), tmp3 = state.at(4*i+3);
        ret.append(mul_bytes(tmp0, 14)^mul_bytes(tmp1, 11)^mul_bytes(tmp2, 13)^mul_bytes(tmp3,  9));
        ret.append(mul_bytes(tmp0,  9)^mul_bytes(tmp1, 14)^mul_bytes(tmp2, 11)^mul_bytes(tmp3, 13));
        ret.append(mul_bytes(tmp0, 13)^mul_bytes(tmp1,  9)^mul_bytes(tmp2, 14)^mul_bytes(tmp3, 11));
        ret.append(mul_bytes(tmp0, 11)^mul_bytes(tmp1, 13)^mul_bytes(tmp2,  9)^mul_bytes(tmp3, 14));
    }
    return ret;
}

quint8 QAES::mul_bytes(const quint8 in1, const quint8 in2){
    return (in1*(in2&1))^(xfer(in1)*((in2>>1)&1)) ^
           (xfer(xfer(in1))*((in2>>2)&1)) ^
           (xfer(xfer(xfer(in1)))*((in2>>3)&1)) ^
            (xfer(xfer(xfer(xfer(in1))))*((in2>>4)&1));
}

QByteArray QAES::crc32(const QByteArray buf, quint32 *c){
    quint32 crc = 0xffffffff;
    foreach(quint8 c, buf)
        crc = (crc >> 8) ^ crc_table.at((crc & 0xff) ^ c);
    if(c != Q_NULLPTR)
        (*c) = crc ^ 0xffffffff;
    QByteArray ret;
    ret.append(((crc ^ 0xffffffff) & 0xff000000) >> 24);
    ret.append(((crc ^ 0xffffffff) & 0xff0000) >> 16);
    ret.append(((crc ^ 0xffffffff) & 0xff00) >> 8);
    ret.append((crc ^ 0xffffffff) & 0xff);
    return ret;
}

bool QAES::headerAES128CBC(QByteArray *ret, const QByteArray filename, const QByteArray buffer, const quint32 *timestamp){
    (*ret) = QByteArray();
    QByteArray filenameData = QByteArray();
    if(!headerFilenameData(&filenameData, filename))
        return false;
    quint32 ts;
    if(timestamp == Q_NULLPTR)
        ts = time(NULL);
    else
        ts = (*timestamp);
    QByteArray ts_bytes = QByteArray();
    ts_bytes.append((ts & 0xff000000) >> 24);
    ts_bytes.append((ts & 0xff0000) >> 16);
    ts_bytes.append((ts & 0xff00) >> 8);
    ts_bytes.append(ts & 0xff);

    QByteArray filesize;
    filesize.append((buffer.length() & 0xff00000000000000) >> 56);
    filesize.append((buffer.length() & 0xff000000000000) >> 48);
    filesize.append((buffer.length() & 0xff0000000000) >> 40);
    filesize.append((buffer.length() & 0xff00000000) >> 32);
    filesize.append((buffer.length() & 0xff000000) >> 24);
    filesize.append((buffer.length() & 0xff0000) >> 16);
    filesize.append((buffer.length() & 0xff00) >> 8);
    filesize.append(buffer.length() & 0xff);
    (*ret) = QByteArray("AES_128_CBC_", 12)+crc32(buffer)+ts_bytes+filesize+filenameData+buffer;
    return true;
}

bool QAES::headerFilenameData(QByteArray *ret, const QByteArray filename){
    (*ret) = QByteArray();
    if((quint64)filename.length() > (quint64)0xffffffff)
        return false;
    (*ret).append((filename.length() & 0xff000000) >> 24);
    (*ret).append((filename.length() & 0xff0000) >> 16);
    (*ret).append((filename.length() & 0xff00) >> 8);
    (*ret).append(filename.length() & 0xff);
    (*ret).append(filename);
    return true;
}

