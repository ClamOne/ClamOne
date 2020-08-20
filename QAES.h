#ifndef QAES_H
#define QAES_H

#include <QObject>
#if QT_VERSION >= 0x050a00
#include <QRandomGenerator>
#endif

class QAES
{

public:
    QAES();
    ~QAES();
    QByteArray lock(const QByteArray filename, const QByteArray buffer, const quint32 *timestamp = Q_NULLPTR);
    QByteArray unlock(const QByteArray buffer, QByteArray *filename = Q_NULLPTR, quint32 *timestamp = Q_NULLPTR, quint64 *file_size = Q_NULLPTR);
    bool verify(const QByteArray buffer, QByteArray *filename = Q_NULLPTR, quint32 *timestamp = Q_NULLPTR, quint64 *file_size = Q_NULLPTR);

private:
    void init_const();
    QByteArray encrypt(const QByteArray filename, const QByteArray buffer, const QByteArray key, const QByteArray iv, const quint32 *timestamp = Q_NULLPTR);
    QByteArray decrypt(const QByteArray buffer, const QByteArray key, const QByteArray iv, QByteArray *filename = Q_NULLPTR, quint32 *timestamp = Q_NULLPTR, quint64 *file_size = Q_NULLPTR);
    QByteArray key_expansion(const QByteArray key);
    QByteArray xor_bytes(const QByteArray in1, const QByteArray in2);
    QByteArray add_round_key(const QByteArray state, const quint8 round_num, const QByteArray round_key);
    QByteArray substitute_bytes(const QByteArray state);
    QByteArray shift_rows(const QByteArray state);
    quint8 xfer(const quint8 in);
    QByteArray mix_columns(const QByteArray state);

    QByteArray inverse_shift_rows(const QByteArray state);
    QByteArray inverse_substitute_bytes(const QByteArray state);
    QByteArray inverse_mix_columns(const QByteArray state);
    quint8 mul_bytes(const quint8 in1, const quint8 in2);

    QByteArray crc32(const QByteArray buf, quint32 *c = Q_NULLPTR);
    bool headerAES128CBC(QByteArray *ret, const QByteArray filename, const QByteArray buffer, const quint32 *timestamp = Q_NULLPTR);
    bool headerFilenameData(QByteArray *ret, const QByteArray filename);

    QByteArray sbox;
    QByteArray rbox;
    QByteArray rcwa;
    QList<quint32> crc_table;
};

#endif // QAESQAES_H
