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

#define IMF_SUB_ENCODE(bits, shift) (((bits) << 8) | (shift))
#define IMF_SUB_GET_BITS(subcode) (((subcode) >> 8) & 0xff)
#define IMF_SUB_GET_SHIFT(subcode) ((subcode) & 0xff)

#define RS_SHIFT 21
#define RT_SHIFT 16
#define RD_SHIFT 11
#define SHAMT_SHIFT 6

#define FIELD_RS        IMF_SUB_ENCODE(5, RS_SHIFT)
#define FIELD_RT        IMF_SUB_ENCODE(5, RT_SHIFT)
#define FIELD_RD        IMF_SUB_ENCODE(5, RD_SHIFT)
#define FIELD_SHAMT     IMF_SUB_ENCODE(5, SHAMT_SHIFT)
#define FIELD_IMMEDIATE IMF_SUB_ENCODE(16, 0)
#define FIELD_DELTA     IMF_SUB_ENCODE(16, 0)
#define FIELD_TARGET    IMF_SUB_ENCODE(26, 0)
#define FIELD_COPZ      IMF_SUB_ENCODE(25, 0)
#define FIELD_CODE      IMF_SUB_ENCODE(10,16)
#define FIELD_PREFX     IMF_SUB_ENCODE(5, 11)
#define FIELD_CACHE     IMF_SUB_ENCODE(5, 16)
#define FIELD_CODE2     IMF_SUB_ENCODE(10, 6)
#define FIELD_CODE20    IMF_SUB_ENCODE(20, 6)
#define FIELD_CODE19    IMF_SUB_ENCODE(19, 6)
#define FIELD_SEL       IMF_SUB_ENCODE(3, 0)
#define FIELD_IGNORE    0

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

#define FLAGS_ALU_I_NO_RS (IMF_SUPPORTED | IMF_ALUSRC | IMF_REGWRITE)
#define FLAGS_ALU_I (IMF_SUPPORTED | IMF_ALUSRC | IMF_REGWRITE | IMF_ALU_REQ_RS)
#define FLAGS_ALU_I_ZE (FLAGS_ALU_I | IMF_ZERO_EXTEND)

#define FLAGS_ALU_I_LOAD (IMF_SUPPORTED | IMF_ALUSRC | IMF_REGWRITE | \
                          IMF_MEMREAD | IMF_MEM | IMF_ALU_REQ_RS)
#define FLAGS_ALU_I_STORE (IMF_SUPPORTED | IMF_ALUSRC | IMF_MEMWRITE | \
                          IMF_MEM | IMF_ALU_REQ_RS | IMF_ALU_REQ_RT)

#define FLAGS_ALU_T_R_D (IMF_SUPPORTED | IMF_REGD | IMF_REGWRITE)
#define FLAGS_ALU_T_R_STD (FLAGS_ALU_T_R_D | IMF_ALU_REQ_RS | IMF_ALU_REQ_RT)
#define FLAGS_ALU_T_R_STD_SHV (FLAGS_ALU_T_R_STD | IMF_ALU_SHIFT)
#define FLAGS_ALU_T_R_TD (FLAGS_ALU_T_R_D | IMF_ALU_REQ_RT)
#define FLAGS_ALU_T_R_TD_SHAMT (FLAGS_ALU_T_R_TD | IMF_ALU_SHIFT)
#define FLAGS_ALU_T_R_S (IMF_SUPPORTED |  IMF_ALU_REQ_RS)
#define FLAGS_ALU_T_R_SD (FLAGS_ALU_T_R_D | IMF_ALU_REQ_RS)
#define FLAGS_ALU_T_R_ST (IMF_SUPPORTED | IMF_ALU_REQ_RS | IMF_ALU_REQ_RT)

#define FLAGS_ALU_TRAP_ST (IMF_SUPPORTED | IMF_ALU_REQ_RS | IMF_ALU_REQ_RT)
#define FLAGS_ALU_TRAP_SI (IMF_SUPPORTED | IMF_ALU_REQ_RS | IMF_ALUSRC)

#define FLAGS_J_B_PC_TO_R31 (IMF_SUPPORTED | IMF_PC_TO_R31 | IMF_REGWRITE)

#define NOALU .alu = ALU_OP_SLL
#define NOMEM .mem_ctl = AC_NONE

#define IM_UNKNOWN {"UNKNOWN", Instruction::T_UNKNOWN, NOALU, NOMEM, nullptr, {}, 0, 0, 0}

struct InstructionMap {
    const char *name;
    enum Instruction::Type type;
    enum AluOp alu;
    enum AccessControl mem_ctl;
    const struct InstructionMap *subclass; // when subclass is used then flags has special meaning
    const QStringList args;
    std::uint32_t code;
    std::uint32_t mask;
    unsigned int flags;
};

#define IT_R Instruction::T_R
#define IT_I Instruction::T_I
#define IT_J Instruction::T_J

const std::int32_t instruction_map_opcode_field = IMF_SUB_ENCODE(6, 26);

// This table is indexed by opcode
static const struct InstructionMap instruction_map[] = {
    {"J",      IT_J, NOALU, NOMEM, nullptr, {"a"}, 0x08000000, 0xfc000000,         // J
     .flags = IMF_SUPPORTED | IMF_JUMP},
    {"JAL",    IT_J, ALU_OP_PASS_T, NOMEM, nullptr, {"a"}, 0x0c000000, 0xfc000000,  // JAL
     .flags = FLAGS_J_B_PC_TO_R31 | IMF_JUMP},
    {"BEQ",    IT_I, NOALU, NOMEM, nullptr, {"s", "t", "p"}, 0x10000000, 0xfc000000,         // BEQ
     .flags = IMF_SUPPORTED | IMF_BJR_REQ_RS | IMF_BJR_REQ_RT | IMF_BRANCH},
    {"BNE",    IT_I, NOALU, NOMEM, nullptr, {"s", "t", "p"}, 0x14000000, 0xfc000000,          // BNE
     .flags = IMF_SUPPORTED | IMF_BJR_REQ_RS | IMF_BJR_REQ_RT | IMF_BRANCH | IMF_BJ_NOT},
    {"BLEZ",   IT_I, NOALU, NOMEM, nullptr, {"s", "p"}, 0x18000000, 0xfc1f0000,          // BLEZ
     .flags = IMF_SUPPORTED | IMF_BJR_REQ_RS | IMF_BRANCH | IMF_BGTZ_BLEZ},
    {"BGTZ",   IT_I, NOALU, NOMEM, nullptr, {"s", "p"}, 0x1c000000, 0xfc1f0000,          // BGTZ
     .flags = IMF_SUPPORTED | IMF_BJR_REQ_RS | IMF_BRANCH | IMF_BGTZ_BLEZ | IMF_BJ_NOT},
    {"ADDI",   IT_I, ALU_OP_ADD, NOMEM, nullptr, {"t", "r", "j"}, 0x20000000, 0xfc000000,     // ADDI
     .flags = FLAGS_ALU_I},
    {"ADDIU",  IT_I, ALU_OP_ADDU, NOMEM, nullptr, {"t", "r", "j"}, 0x24000000, 0xfc000000,    // ADDIU
     .flags = FLAGS_ALU_I},
    {"SLTI",   IT_I, ALU_OP_SLT, NOMEM, nullptr, {"t", "r", "j"}, 0x28000000, 0xfc000000,     // SLTI
     .flags = FLAGS_ALU_I},
    {"SLTIU",  IT_I, ALU_OP_SLTU, NOMEM, nullptr, {"t", "r", "j"}, 0x2c000000, 0xfc000000,    // SLTIU
     .flags = FLAGS_ALU_I},
    {"ANDI",   IT_I, ALU_OP_AND, NOMEM, nullptr, {"t", "r", "i"}, 0x30000000, 0xfc000000,     // ANDI
     .flags = FLAGS_ALU_I_ZE},
    {"ORI",    IT_I, ALU_OP_OR, NOMEM, nullptr, {"t", "r", "i"}, 0x34000000, 0xfc000000,      // ORI
     .flags = FLAGS_ALU_I_ZE},
    {"XORI",   IT_I, ALU_OP_XOR, NOMEM, nullptr, {"t", "r", "i"}, 0x38000000, 0xfc000000,     // XORI
     .flags = FLAGS_ALU_I_ZE},
    {"LUI",    IT_I, ALU_OP_LUI, NOMEM, nullptr, {"t", "u"}, 0x3c000000, 0xffe00000,     // LUI
     .flags = FLAGS_ALU_I_NO_RS},
    IM_UNKNOWN,  // 17
    IM_UNKNOWN,  // 18
    IM_UNKNOWN,  // 19
    {"BEQL",    IT_I, NOALU, NOMEM, nullptr, {"s", "t", "p"}, 0x50000000, 0xfc000000,         // BEQL
     .flags = IMF_SUPPORTED | IMF_BJR_REQ_RS | IMF_BJR_REQ_RT | IMF_BRANCH | IMF_NB_SKIP_DS},
    {"BNEL",    IT_I, NOALU, NOMEM, nullptr, {"s", "t", "p"}, 0x54000000, 0xfc000000,         // BNEL
     .flags = IMF_SUPPORTED | IMF_BJR_REQ_RS | IMF_BJR_REQ_RT | IMF_BRANCH | IMF_NB_SKIP_DS | IMF_BJ_NOT},
    {"BLEZL",   IT_I, NOALU, NOMEM, nullptr, {"s", "p"}, 0x58000000, 0xfc1f0000,         // BLEZL
     .flags = IMF_SUPPORTED | IMF_BJR_REQ_RS | IMF_BRANCH | IMF_NB_SKIP_DS | IMF_BGTZ_BLEZ},
    {"BGTZL",   IT_I, NOALU, NOMEM, nullptr, {"s", "p"}, 0x5c000000, 0xfc1f0000,         // BGTZL
     .flags = IMF_SUPPORTED | IMF_BJR_REQ_RS | IMF_BRANCH | IMF_NB_SKIP_DS | IMF_BGTZ_BLEZ | IMF_BJ_NOT},
    IM_UNKNOWN,  // 24
    IM_UNKNOWN,  // 25
    IM_UNKNOWN,  // 26
    IM_UNKNOWN,  // 27
    IM_UNKNOWN,  // 29
    IM_UNKNOWN,  // 30
    {"LB",     IT_I, ALU_OP_ADDU, AC_BYTE, nullptr, {"t", "o(b)"}, 0x80000000, 0xfc000000,  // LB
     .flags = FLAGS_ALU_I_LOAD},
    {"LH",     IT_I, ALU_OP_ADDU, AC_HALFWORD, nullptr, {"t", "o(b)"}, 0x84000000, 0xfc000000,  // LH
     .flags = FLAGS_ALU_I_LOAD},
    {"LWL",    IT_I, ALU_OP_ADDU, AC_WORD_LEFT, nullptr, {"t", "o(b)"}, 0x88000000, 0xfc000000,    // LWL - unsupported
     .flags = FLAGS_ALU_I_LOAD | IMF_ALU_REQ_RT},
    {"LW",     IT_I, ALU_OP_ADDU, AC_WORD, nullptr, {"t", "o(b)"}, 0x8c000000, 0xfc000000,  // LW
     .flags = FLAGS_ALU_I_LOAD},
    {"LBU",    IT_I, ALU_OP_ADDU, AC_BYTE_UNSIGNED, nullptr, {"t", "o(b)"}, 0x90000000, 0xfc000000,  // LBU
     .flags = FLAGS_ALU_I_LOAD},
    {"LHU",    IT_I, ALU_OP_ADDU, AC_HALFWORD_UNSIGNED, nullptr, {"t", "o(b)"}, 0x94000000, 0xfc000000,   // LHU
     .flags = FLAGS_ALU_I_LOAD},
    {"LWR",    IT_I, ALU_OP_ADDU, AC_WORD_RIGHT, nullptr, {"t", "o(b)"}, 0x98000000, 0xfc000000,    // LWR - unsupported
     .flags = FLAGS_ALU_I_LOAD | IMF_ALU_REQ_RT},
    IM_UNKNOWN,  // 39
    {"SB",     IT_I, ALU_OP_ADDU, AC_BYTE, nullptr, {"t", "o(b)"}, 0xa0000000, 0xfc000000,  // SB
     .flags = FLAGS_ALU_I_STORE},
    {"SH",     IT_I, ALU_OP_ADDU, AC_HALFWORD, nullptr, {"t", "o(b)"}, 0xa4000000, 0xfc000000,   // SH
     .flags = FLAGS_ALU_I_STORE},
    {"SWL",    IT_I, ALU_OP_ADDU, AC_WORD_LEFT, nullptr, {"t", "o(b)"}, 0xa8000000, 0xfc000000,    // SWL
     .flags = FLAGS_ALU_I_STORE},
    {"SW",     IT_I, ALU_OP_ADDU, AC_WORD, nullptr, {"t", "o(b)"}, 0xac000000, 0xfc000000,  // SW
     .flags = FLAGS_ALU_I_STORE},
    IM_UNKNOWN,  // 44
    IM_UNKNOWN,  // 45
    {"SWR",    IT_I, ALU_OP_ADDU, AC_WORD_RIGHT, nullptr, {"t", "o(b)"}, 0xb8000000, 0xfc000000,    // SWR
     .flags = FLAGS_ALU_I_STORE},
    {"CACHE",  IT_I, ALU_OP_ADDU, AC_CACHE_OP, nullptr, {"k", "o(b)"}, 0xbc000000, 0xfc000000, // CACHE
     .flags = IMF_SUPPORTED | IMF_ALUSRC | IMF_MEM},
    {"LL",     IT_I, ALU_OP_ADDU, AC_LOAD_LINKED, nullptr, {"t", "o(b)"}, 0xc0000000, 0xfc000000,  // LL
     .flags = FLAGS_ALU_I_LOAD},
    {"LWC1", IT_I, NOALU, NOMEM, nullptr, {"T", "o(b)"}, 0xc4000000, 0xfc000000,
     .flags = IMF_SUPPORTED},
    IM_UNKNOWN,  // 50
    {"PREF", IT_I, NOALU, NOMEM, nullptr, {"k", "o(b)"}, 0xcc000000, 0xfc000000,            // PREF
     .flags = IMF_SUPPORTED},
    IM_UNKNOWN,  // 52
    {"LWD1", IT_I, NOALU, NOMEM, nullptr, {"T", "o(b)"}, 0xd4000000, 0xfc000000,
     .flags = IMF_SUPPORTED},
    IM_UNKNOWN,  // 54
    IM_UNKNOWN,  // 55
    {"SC",     IT_I, ALU_OP_ADDU, AC_STORE_CONDITIONAL, nullptr, {"t", "o(b)"}, 0xe0000000, 0xfc000000,  // SW
     .flags = FLAGS_ALU_I_STORE | IMF_MEMREAD | IMF_REGWRITE},
    {"SWC1", IT_I, NOALU, NOMEM, nullptr, {"T", "o(b)"}, 0xe4000000, 0xfc000000,
     .flags = IMF_SUPPORTED},
    IM_UNKNOWN,  // 58
    IM_UNKNOWN,  // 59
    IM_UNKNOWN,  // 60
    {"SDC1", IT_I, NOALU, NOMEM, nullptr, {"T", "o(b)"}, 0xf4000000, 0xfc000000,
     .flags = IMF_SUPPORTED},
    IM_UNKNOWN,  // 62
    IM_UNKNOWN,  // 63
};

#undef IM_UNKNOWN

static inline const struct InstructionMap &InstructionMapFind(std::uint32_t code) {
    const struct InstructionMap *im = instruction_map;
    std::uint32_t flags = instruction_map_opcode_field;
    do {
        unsigned int bits = IMF_SUB_GET_BITS(flags);
        unsigned int shift = IMF_SUB_GET_SHIFT(flags);
        im = im + ((code >> shift) & ((1 << bits) - 1));
        if (im->subclass == nullptr)
            return *im;
        flags = im->flags;
        im = im->subclass;
    } while(1);
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

#define MASK(LEN,OFF) ((this->dt >> (OFF)) & ((1 << (LEN)) - 1))

std::uint8_t Instruction::opcode() const {
    return (std::uint8_t) MASK(6, 26);
}

std::uint8_t Instruction::rs() const {
    return (std::uint8_t) MASK(5, RS_SHIFT);
}

std::uint8_t Instruction::rt() const {
    return (std::uint8_t) MASK(5, RT_SHIFT);
}

std::uint8_t Instruction::rd() const {
    return (std::uint8_t) MASK(5, RD_SHIFT);
}

std::uint8_t Instruction::shamt() const {
    return (std::uint8_t) MASK(5, SHAMT_SHIFT);

}

std::uint8_t Instruction::funct() const {
    return (std::uint8_t) MASK(6, 0);
}

std::uint8_t Instruction::cop0sel() const {
    return (std::uint8_t) MASK(3, 0);
}

std::uint16_t Instruction::immediate() const {
    return (std::uint16_t) MASK(16, 0);
}

std::uint32_t Instruction::address() const {
    return (std::uint32_t) MASK(26, 0);
}

std::uint32_t Instruction::data() const {
    return this->dt;
}

enum Instruction::Type Instruction::type() const {
    const struct InstructionMap &im = InstructionMapFind(dt);
    return im.type;
}

enum InstructionFlags Instruction::flags() const {
    const struct InstructionMap &im = InstructionMapFind(dt);
    return (enum InstructionFlags)im.flags;
}
enum AluOp Instruction::alu_op() const {
    const struct InstructionMap &im = InstructionMapFind(dt);
    return im.alu;
}

enum AccessControl Instruction::mem_ctl() const {
    const struct InstructionMap &im = InstructionMapFind(dt);
    return im.mem_ctl;
}

void Instruction::flags_alu_op_mem_ctl(enum InstructionFlags &flags,
                  enum AluOp &alu_op, enum AccessControl &mem_ctl) const {
    const struct InstructionMap &im = InstructionMapFind(dt);
    flags = (enum InstructionFlags)im.flags;
    alu_op = im.alu;
    mem_ctl = im.mem_ctl;
   #if 1
    if ((dt ^ im.code) & (im.mask))
        flags = (enum InstructionFlags)(flags & ~IMF_SUPPORTED);
   #endif
}

enum ExceptionCause Instruction::encoded_exception() const {
    const struct InstructionMap &im = InstructionMapFind(dt);
    if (!(im.flags & IMF_EXCEPTION))
        return EXCAUSE_NONE;
    switch (im.alu) {
        case ALU_OP_BREAK:
            return EXCAUSE_BREAK;
        case ALU_OP_SYSCALL:
            return EXCAUSE_SYSCALL;
        default:
            return EXCAUSE_NONE;
    }
}

bool Instruction::is_break() const {
    const struct InstructionMap &im = InstructionMapFind(dt);
    return im.alu == ALU_OP_BREAK;
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
    if (im.type == T_UNKNOWN)
        return QString("UNKNOWN");

    res += im.name;
    return res;
}

QMultiMap<QString, std::uint32_t> str_to_instruction_code_map;

void instruction_from_string_build_base(const InstructionMap *im = nullptr,
                    unsigned int flags = 0, std::uint32_t base_code = 0) {
    std::uint32_t code;

    if (im == nullptr) {
        im = instruction_map;
        flags = instruction_map_opcode_field;
        base_code = 0;
    }
    unsigned int bits = IMF_SUB_GET_BITS(flags);
    unsigned int shift = IMF_SUB_GET_SHIFT(flags);

    for (unsigned int i = 0; i < 1U << bits; i++, im++) {
        code = base_code | (i << shift);
        if (im->subclass) {
            instruction_from_string_build_base(im->subclass, im->flags, code);
            continue;
        }
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
