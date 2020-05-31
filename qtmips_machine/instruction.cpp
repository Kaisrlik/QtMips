// vim: set expandtab:
// SPDX-License-Identifier: GPL-2.0+
/*******************************************************************************
 * QtMips - MIPS 32-bit Architecture Subset Simulator
 *
 * Implemented to support following courses:
 *
 *   B35APO - Computer Architectures
 *   https://cw.fel.cvut.cz/wiki/courses/b35apo
 *
 *   B4M35PAP - Advanced Computer Architectures
 *   https://cw.fel.cvut.cz/wiki/courses/b4m35pap/start
 *
 * Copyright (c) 2017-2019 Karel Koci<cynerd@email.cz>
 * Copyright (c) 2019      Pavel Pisa <pisa@cmp.felk.cvut.cz>
 *
 * Faculty of Electrical Engineering (http://www.fel.cvut.cz)
 * Czech Technical University        (http://www.cvut.cz/)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 ******************************************************************************/

#include <QMultiMap>
#include <QVector>
#include <QStringList>
#include <QChar>
#include <iostream>
#include <cctype>
#include <cstring>
#include "instruction.h"
#include "alu.h"
#include "memory.h"
#include "utils.h"
#include "qtmipsexception.h"

using namespace machine;

struct RegisterDesc {
    int kind;
    int number;
    const char *name;
};

const RegisterDesc regbycode[] = {
    [0] = {0, 0, "zero"},
    [1] = {0, 1, "at"},
    [2] = {0, 2, "v0"},
    [3] = {0, 3, "v1"},
    [4] = {0, 4, "a0"},
    [5] = {0, 5, "a1"},
    [6] = {0, 6, "a2"},
    [7] = {0, 7, "a3"},
    [8] = {0, 8, "t0"},
    [9] = {0, 9, "t1"},
    [10] = {0, 10, "t2"},
    [11] = {0, 11, "t3"},
    [12] = {0, 12, "t4"},
    [13] = {0, 13, "t5"},
    [14] = {0, 14, "t6"},
    [15] = {0, 15, "t7"},
    [16] = {0, 16, "s0"},
    [17] = {0, 17, "s1"},
    [18] = {0, 18, "s2"},
    [19] = {0, 19, "s3"},
    [20] = {0, 20, "s4"},
    [21] = {0, 21, "s5"},
    [22] = {0, 22, "s6"},
    [23] = {0, 23, "s7"},
    [24] = {0, 24, "t8"},
    [25] = {0, 25, "t9"},
    [26] = {0, 26, "k0"},
    [27] = {0, 27, "k1"},
    [28] = {0, 28, "gp"},
    [29] = {0, 29, "sp"},
    [30] = {0, 30, "s8"},
    [31] = {0, 31, "ra"},
};

struct InstructionMap {
    const char *name;
    enum AluOp alu;
    enum AccessControl mem_ctl;
    const QStringList args;
    std::uint32_t code;
    std::uint32_t mask;
    unsigned int flags;
};

// This table is indexed by opcode
// last n-bits with set values defines size of instruction set
// r-type map - 0-6 opcode, 7 - 11 rd, 12-14 func3, 15 - 19 rs1, 20-24 rs2, 25 - 31 func7
// i-type map - 0-6 opcode, 7 - 11 rd, 12-14 func3, 15 - 19 rs1, 20 - 31 imm
// s-type map - 0-6 opcode, 7 - 11 im, 12-14 func3, 15 - 19 rs1, 20-24 rs2, 25 - 31 imm
// b-type map - 0-6 opcode, 7     imm,  8-11 imm  , 12-14 func3, 15 - 19 rs1, 20-24 rs2, 25 - 30 imm, 31 imm
// u-type map - 0-6 opcode, 7 - 11 rd, 12 - 31 imm
// j-type map - 0-6 opcode, 7 - 11 rd, 12 - 19 imm, 20 - 30 imm, 31 im
#define RTYPE_OPCODE_MASK 0b11111110000000000111000001111111
#define BTYPE_OPCODE_MASK 0b00000000000000000111000001111111
#define ITYPE_OPCODE_MASK BTYPE_OPCODE_MASK
#define STYPE_OPCODE_MASK BTYPE_OPCODE_MASK
#define UTYPE_OPCODE_MASK 0b00000000000000000000000001111111
#define JTYPE_OPCODE_MASK UTYPE_OPCODE_MASK

#define OPCODE_LUI      0b00000000000000000000000000110111
#define OPCODE_LUI_MASK UTYPE_OPCODE_MASK
#define OPCODE_AUIPC      0b00000000000000000000000000010111
#define OPCODE_AUIPC_MASK UTYPE_OPCODE_MASK
#define OPCODE_JAL      0b00000000000000000000000000110111
#define OPCODE_JAL_MASK UTYPE_OPCODE_MASK
const std::map<uint32_t, Instruction> instruction_set = {};
//     {OPCODE_LUI, {"LUI", ALU_OP_SLL, AC_NONE, NULL, 0, 0, 0} },
// };

static inline const struct InstructionMap &InstructionMapFind(std::uint32_t code) {
    // order dependnet, the biggest mask goes first
    if (instruction_set.count(code & RTYPE_OPCODE_MASK))
        return instruction_set[code & RTYPE_OPCODE_MASK];
    if (instruction_set.count(code & BTYPE_OPCODE_MASK))
        return instruction_set[code & BTYPE_OPCODE_MASK];
    if (instruction_set.count(code & UTYPE_OPCODE_MASK))
        return instruction_set[code & UTYPE_OPCODE_MASK];
    return NULL;
}

Instruction::Instruction() {
    this->dt = 0;
}

Instruction::Instruction(std::uint32_t inst) {
    this->dt = inst;
}

Instruction::Instruction(std::uint8_t opcode, std::uint8_t rs, std::uint8_t rt, std::uint8_t rd, std::uint8_t shamt, std::uint8_t funct) {
    this->dt = 0;
    this->dt |= opcode << 26;
    this->dt |= rs << 21;
    this->dt |= rt << 16;
    this->dt |= rd << 11;
    this->dt |= shamt << 6;
    this->dt |= funct;
}

Instruction::Instruction(std::uint8_t opcode, std::uint8_t rs, std::uint8_t rt, std::uint16_t immediate) {
    this->dt = 0;
    this->dt |= opcode << 26;
    this->dt |= rs << 21;
    this->dt |= rt << 16;
    this->dt |= immediate;
}

Instruction::Instruction(std::uint8_t opcode, std::uint32_t address) {
    this->dt = 0;
    this->dt |= opcode << 26;
    this->dt |= address;
}

Instruction::Instruction(const Instruction &i) {
    this->dt = i.data();
}

std::uint8_t Instruction::opcode() const {
    return 0;
}

std::uint8_t Instruction::rs() const {
    return 0;
}

std::uint8_t Instruction::rt() const {
    return 0;
}

std::uint8_t Instruction::rd() const {
    return 0;
}

std::uint8_t Instruction::shamt() const {
    return 0;
}

std::uint8_t Instruction::funct() const {
    return 0;
}

std::uint8_t Instruction::cop0sel() const {
    return 0;
}

std::uint16_t Instruction::immediate() const {
    return 0;
}

std::uint32_t Instruction::address() const {
    return 0;
}

std::uint32_t Instruction::data() const {
    return 0;
}


void Instruction::flags_alu_op_mem_ctl(enum InstructionFlags &flags,
                  enum AluOp &alu_op, enum AccessControl &mem_ctl) const {
    const struct InstructionMap &im = InstructionMapFind(dt);
}

enum ExceptionCause Instruction::encoded_exception() const {
    return EXCAUSE_NONE;
}

bool Instruction::operator==(const Instruction &c) const {
    return (this->data() == c.data());
}

bool Instruction::operator!=(const Instruction &c) const {
    return ! this->operator==(c);
}

Instruction &Instruction::operator=(const Instruction &c) {
    if (this != &c)
        this->dt = c.data();
    return *this;
}

QString Instruction::to_str(std::int32_t inst_addr) const {
    const InstructionMap &im = InstructionMapFind(dt);
    // TODO there are exception where some fields are zero and such so we should not print them in such case
    if (dt == 0)
        return QString("NOP");
    QString res;
    QString next_delim = " ";

    res += im.name;
    return res;
}

QMultiMap<QString, std::uint32_t> str_to_instruction_code_map;

void instruction_from_string_build_base(const InstructionMap *im = nullptr,
                    unsigned int flags = 0, std::uint32_t base_code = 0) {
    std::uint32_t code;

    if (im == nullptr) {
        im = NULL;
        flags = 0;
        base_code = 0;
    }
    unsigned int bits = 0;
    unsigned int shift = 0;

    for (unsigned int i = 0; i < 1U << bits; i++, im++) {
        code = base_code | (i << shift);
        if (!(im->flags & IMF_SUPPORTED))
            continue;
        if (im->code != code) {
#if 0
            printf("code mitchmatch %s computed 0x%08x found 0x%08x\n", im->name, code, im->code);
#endif
            continue;
        }
        str_to_instruction_code_map.insert(im->name, code);
    }
#if 0
    for (auto i = str_to_instruction_code_map.begin();
         i != str_to_instruction_code_map.end(); i++)
        std::cout << i.key().toStdString() << ' ';
#endif
}

static int parse_reg_from_string(QString str, uint *chars_taken = nullptr)
{
    int res;
    int i;
    uint ctk;
    if (str.count() < 2 || str.at(0) != '$')
        return -1;

    if (str.at(1).isLetter()) {
        int k = 1;
        while(k < str.count()) {
            if (!str.at(k).isLetterOrNumber())
                break;
            k++;
        }
        str = str.mid(1, k-1);
        for (i = 0 ; i < sizeof(regbycode); i++) {
            if (str == regbycode[i].name) {
                if (chars_taken != nullptr)
                   *chars_taken = k;
                return regbycode[i].number;
            }
        }
        return -1;
    }

    char cstr[str.count() + 1];
    for (i = 0; i < str.count(); i++)
        cstr[i] = str.at(i).toLatin1();
    cstr[i] = 0;
    const char *p = cstr + 1;
    char *r;
    res = std::strtol(p, &r, 0);
    ctk = r - p + 1;
    if (p == r)
        return -1;
    if (res > 31)
        return -1;
    if (chars_taken != nullptr)
        *chars_taken = ctk;
    return res;
}

#define CFS_OPTION_SILENT_MASK 0x100

ssize_t Instruction::code_from_string(std::uint32_t *code, size_t buffsize,
                       QString inst_base, QStringList &inst_fields, QString &error,
                       std::uint32_t inst_addr, RelocExpressionList *reloc,
                       QString filename, int line, bool pseudo_opt, int options)
{
    const char *err = "unknown instruction";
    if (str_to_instruction_code_map.isEmpty())
        instruction_from_string_build_base();

    int field = 0;
    std::uint32_t inst_code = 0;
    auto i = str_to_instruction_code_map.lowerBound(inst_base);
    for (; ; i++) {
        if (i == str_to_instruction_code_map.end())
            break;
        if (i.key() != inst_base)
            break;
        inst_code = i.value();
        const InstructionMap &im = InstructionMapFind(inst_code);

        field = 0;
        if (field != inst_fields.count())
            continue;

        if (buffsize >= 4)
            *code = inst_code;
        return 4;
    }

    ssize_t ret = -1;
    inst_code = 0;
    if ((inst_base == "NOP") && (inst_fields.size() == 0)) {
        inst_code = 0;
        ret = 4;
    } else if (pseudo_opt) {
        if (((inst_base == "LA") || (inst_base == "LI")) && (inst_fields.size() == 2)) {
            if(code_from_string(code, buffsize, "LUI", inst_fields, error,
                             inst_addr, reloc, filename, line, false,
                             CFS_OPTION_SILENT_MASK + 16) < 0) {
                error = QString("error in LUI element of " + inst_base);
                return -1;
            }
            inst_fields.insert(1, inst_fields.at(0));
            if (code_from_string(code + 1, buffsize - 4, "ORI", inst_fields, error,
                             inst_addr + 4, reloc, filename, line, false,
                             CFS_OPTION_SILENT_MASK + 0) < 0) {
                error = QString("error in ORI element of " + inst_base);
                return -1;
            }
            return 8;
        }
    }
    if (buffsize >= 4)
        *code = inst_code;
    if (ret < 0) {
        error = err;
    }
    return ret;
}

ssize_t Instruction::code_from_string(std::uint32_t *code, size_t buffsize,
                       QString str, QString &error, std::uint32_t inst_addr,
                       RelocExpressionList *reloc, QString filename, int line,
                       bool pseudo_opt, int options)
{
    int k = 0, l;
    while (k < str.count()) {
        if (!str.at(k).isSpace())
            break;
        k++;
    }
    l = k;
    while (l < str.count()) {
        if (!str.at(l).isLetterOrNumber())
            break;
        l++;
    }
    QString inst_base = str.mid(k, l - k).toUpper();
    str = str.mid(l + 1).trimmed();
    QStringList inst_fields;
    if (str.count())
        inst_fields = str.split(",");

    if (!inst_base.count()) {
        error = "empty instruction field";
        return -1;
    }

    return code_from_string(code, buffsize, inst_base, inst_fields, error, inst_addr,
                            reloc, filename, line, pseudo_opt, options);
}

bool Instruction::update(std::int64_t val, RelocExpression *relocexp) {
    std::int64_t mask = (((std::int64_t)1 << relocexp->bits) - 1) << relocexp->lsb_bit;
    dt &= ~ mask;
    val += relocexp->offset;
    if ((val & ((1 << relocexp->shift) - 1)) &&
        !(relocexp->options & CFS_OPTION_SILENT_MASK)) {
        return false;
    }
    int shift_right = relocexp->shift + (relocexp->options & 0xff);
    if (relocexp->min >= 0)
        val = (val >> shift_right) ;
    else
        val = (std::uint64_t)((std::int64_t)val >> shift_right);
    if (!(relocexp->options & CFS_OPTION_SILENT_MASK)) {
        if (relocexp->min < 0) {
            if (((std::int64_t)val < relocexp->min) ||
                ((std::int64_t)val > relocexp->max)) {
                if (((std::int64_t)val - 0x100000000 < relocexp->min) ||
                    ((std::int64_t)val - 0x100000000 > relocexp->max))
                    return false;
            }
        } else {
            if (((std::uint64_t)val < (std::uint64_t)relocexp->min) ||
                ((std::uint64_t)val > (std::uint64_t)relocexp->max)) {
                return false;
            }
        }
    }
    dt |= (val << relocexp->lsb_bit) & mask;
    return true;
}

void Instruction::append_recognized_instructions(QStringList &list) { }
void Instruction::append_recognized_registers(QStringList &list) { }
