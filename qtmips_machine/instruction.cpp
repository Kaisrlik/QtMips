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
// This table is indexed by opcode
// last n-bits with set values defines size of instruction set
// r-type map - 0-6 opcode, 7 - 11 rd, 12-14 func3, 15 - 19 rs1, 20-24 rs2, 25 - 31 func7
// i-type map - 0-6 opcode, 7 - 11 rd, 12-14 func3, 15 - 19 rs1, 20 - 31 imm
// s-type map - 0-6 opcode, 7 - 11 im, 12-14 func3, 15 - 19 rs1, 20-24 rs2, 25 - 31 imm
// b-type map - 0-6 opcode, 7     imm,  8-11 imm  , 12-14 func3, 15 - 19 rs1, 20-24 rs2, 25 - 30 imm, 31 imm
// u-type map - 0-6 opcode, 7 - 11 rd, 12 - 31 imm
// j-type map - 0-6 opcode, 7 - 11 rd, 12 - 19 imm, 20 - 30 imm, 31 im
// Mask is probably wrong
#include <byteswap.h>
// using same bitorder as described in ISA, so it means we have to change
// bitorder everywhere :(
#define RTYPE_OPCODE_MASK __bswap_32(0b11111110000000000111000001111111)
#define BTYPE_OPCODE_MASK __bswap_32(0b00000000000000000111000001111111)
#define ITYPE_OPCODE_MASK BTYPE_OPCODE_MASK
#define STYPE_OPCODE_MASK BTYPE_OPCODE_MASK
#define UTYPE_OPCODE_MASK __bswap_32(0b00000000000000000000000001111111)
#define JTYPE_OPCODE_MASK UTYPE_OPCODE_MASK

#define UTYPE_RD_MASK     __bswap_32(0b00000000000000000000111110000000)
#define UTYPE_RD_SHIFT    20
#define UTYPE_IMM_MASK    __bswap_32(0b11111111111111111111000000000000)

#define OPCODE_LUI   __bswap_32(0b00000000000000000000000000110111)
#define OPCODE_LUI_MASK UTYPE_OPCODE_MASK
#define OPCODE_AUIPC __bswap_32(0b00000000000000000000000000010111)
#define OPCODE_AUIPC_MASK UTYPE_OPCODE_MASK
#define OPCODE_JAL   __bswap_32(0b00000000000000000000000000110111)
#define OPCODE_JAL_MASK UTYPE_OPCODE_MASK

const std::map<uint32_t, InstructionMap> instruction_set = {
    {OPCODE_LUI, {"LUI", ALU_OP_SLL, AC_NONE, {}, 0, 0, IMF_SUPPORTED | IMF_ALUSRC | IMF_REGWRITE} },
    // NOP does not exist in ISA - it is replaced by ADDI x0,x0,0
    {0, {"NOP", ALU_OP_SLL, AC_NONE, {}, 0, 0, IMF_SUPPORTED | IMF_ALUSRC} },
};
const InstructionMap IM_UNKNOWN = {"UNKNOWN", ALU_OP_SLL, AC_NONE, {}, 0, 0, 0};

static inline const struct InstructionMap * InstructionMapFind(std::uint32_t code) {
    // order dependnet, the biggest mask goes first
    if (instruction_set.count(code & RTYPE_OPCODE_MASK))
        return &instruction_set.at(code & RTYPE_OPCODE_MASK);
    if (instruction_set.count(code & BTYPE_OPCODE_MASK))
        return &instruction_set.at(code & BTYPE_OPCODE_MASK);
    if (instruction_set.count(code & UTYPE_OPCODE_MASK))
        return &instruction_set.at(code & UTYPE_OPCODE_MASK);
    return &IM_UNKNOWN;
}

Instruction::Instruction() {
    this->dt = 0;
    this->current_instruction = &IM_UNKNOWN;
}

Instruction::Instruction(std::uint32_t inst) {
    this->dt = inst;
    this->current_instruction = InstructionMapFind(this->dt);
    printf("%s:%s:%d: Instruction 0x%08x (%s) created. \n", __FILE__, __func__, __LINE__,
            this->dt, this->current_instruction->name);
}

Instruction::Instruction(const Instruction &i) {
    this->dt = i.data();
    this->current_instruction = InstructionMapFind(this->dt);
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
    return this->dt;
}

// get flags, alu op, and memctl
void Instruction::flags_alu_op_mem_ctl(enum InstructionFlags &flags,
                  enum AluOp &alu_op, enum AccessControl &mem_ctl) const {
    flags = (enum InstructionFlags)this->current_instruction->flags;
    alu_op = this->current_instruction->alu;
    mem_ctl = this->current_instruction->mem_ctl;
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
    (void) inst_addr; //unused
    const InstructionMap * im = this->current_instruction;
    QString res;
    res += im->name;
    // TODO: maybe it is possible to use library able to convert machine code to
    // asm.  and laso i would like to move it to common place to have same
    // parsig(printing) function
    if (instruction_set.count(this->dt & RTYPE_OPCODE_MASK))
        res += "";
    if (instruction_set.count(this->dt & BTYPE_OPCODE_MASK))
        res += "";
    if (instruction_set.count(this->dt & UTYPE_OPCODE_MASK))
        res += " $" + QString::number((this->dt & UTYPE_RD_MASK) >> UTYPE_RD_SHIFT) 
            + ", $" + QString::number(this->dt & UTYPE_IMM_MASK);
    return res;
}

QMultiMap<QString, std::uint32_t> str_to_instruction_code_map;

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
    return 0;
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
