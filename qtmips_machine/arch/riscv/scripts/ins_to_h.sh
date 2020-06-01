#!/bin/bash

# $ a='hello:world:of:tomorrow'
# $ echo "${a%:*}"
# hello:world:of
# $ echo "${a%%:*}"
# hello
# $ echo "${a#*:}"
# world:of:tomorrow
# $ echo "${a##*:}"
# tomorrow

function define_opcode() {
	opcode=$(printf "0b%032s\n" $(bc <<< "ibase=2;obase=2;$2") | sed 's/ /0/g')
	echo "#define $1_OPCODE __bswap_32($opcode << $3)" >> $o
}
function define_opcode_merge() {
	x="#define $1_OPCODE"
	for (( i = 0; i < $2; i++ )); do
		x="$x ${1}${i}_OPCODE |"
	done
	if [[ $2 -ne 0 ]]; then
		echo ${x::-2} >> $o
		return
	fi
	echo "$1 NO Opcede"
}
function define_shift() {
	echo "#define $1_$2_SHIFT $3" >> $o
}
function define_mask() {
	_x=""
	for (( i = 0; i < $3; i++ )); do
		_x="${_x}1"
	done
	mask=$(printf "0b%032s\n" $(bc <<< "ibase=2;obase=2;$_x") | sed 's/ /0/g')
	echo "#define $1_$2_MASK __bswap_32($mask << $4)" >> $o
}

function parse() {
	inst="$1"
	opcode_cnt=0
	imm_cnt=0
	name="${inst##*1}"
	name="${name##*0}"
	name=$(echo $name | sed 's/\.//g')
	len=32
	while [[ 1 ]]; do
		if [[ "$inst" == imm* ]]; then
			imm="${inst%%]*}]"
			inst="${inst#*]}"
			# remove parental
			imm="${imm%]*}"
			imm="${imm#*[}"
			l="0"
			# devided by pipe
			while [[ ! -z ${imm} ]]; do
# 				echo "imm start $imm"
				if [[ $(echo $imm | grep "|" | wc -l) -eq 1 ]]; then
# 					echo "contains |"
					x=${imm%%|*}
					imm=${imm#*|}
				else
					x=${imm}
					imm=""
				fi
# 				echo "spit - $x and $imm"
				if [[ $(echo $x | grep ":" | wc -l) -eq 1 ]]; then
					l=$(( $l + $(echo ${x} | awk -F: '{print $1}') - $(echo ${x} | awk -F: '{print $2}') + 1 ))
				else
					l=$(($l + 1))
				fi
			done
			len=$((${len} - ${l} ))
			define_shift $name$imm_cnt IMM $len
			define_mask $name$imm_cnt IMM $l $len
			imm_cnt=$(($imm_cnt + 1))
# 			echo ${imm} and ${inst} $l - remaining ${len}
		fi
		# regs
		if [[ "$inst" == rd* ]]; then
			imm="${inst%%d*}d"
			inst="${inst#*d}"
			l=$((11 - 7 + 1))
			len=$((${len} - ${l}))
# 			echo ${imm} and ${inst} $l remaining ${len}
			define_shift $name RD $len
			define_mask $name RD $l $len
		fi
		if [[ "$inst" == rs1* ]]; then
			imm="${inst%%1*}1"
			inst="${inst#*1}"
			l=$((11 - 7 + 1))
			len=$((${len} - ${l}))
# 			echo ${imm} and ${inst} $l remaining ${len}
			define_shift $name RS1 $len
			define_mask $name RS1 $l $len
		fi
		if [[ "$inst" == rs2* ]]; then
			imm="${inst%%2*}2"
			inst="${inst#*2}"
			l=$((11 - 7 + 1))
			len=$((${len} - ${l}))
# 			echo ${imm} and ${inst} $l remaining ${len}
			define_shift $name RS2 $len
			define_mask $name RS2 $l $len
		fi
		if [[ "$inst" == shamt* ]]; then
			imm="${inst%%t*}t"
			inst="${inst#*t}"
			l=$((11 - 7 + 1))
			len=$((${len} - ${l}))
# 			echo ${imm} and ${inst} $l remaining ${len}
			define_shift $name SHAMT $len
			define_mask $name SHAMT $l $len
		fi
		if [[ "$inst" == pred* ]]; then
			imm="${inst%%d*}d"
			inst="${inst#*d}"
			l=$((4))
			len=$((${len} - ${l}))
# 			echo ${imm} and ${inst} $l remaining ${len}
			define_shift $name PRED $len
			define_mask $name PRED $l $len
		fi
		if [[ "$inst" == succ* ]]; then
			imm="${inst%%c*}"
			imm="${inst%%c*}c"
			inst="${inst#*c}"
			inst="${inst#*c}"
			l=$((4))
			len=$((${len} - ${l}))
# 			echo ${imm} and ${inst} $l remaining ${len}
			define_shift $name SUCC $len
			define_mask $name SUCC $l $len
		fi
		if [[ "$inst" == csr* ]]; then
			imm="${inst%%r*}r"
			inst="${inst#*r}"
			l=$((12))
			len=$((${len} - ${l}))
# 			echo ${imm} and ${inst} $l remaining ${len}
			define_shift $name CRS $len
			define_mask $name CRS $l $len
		fi
		if [[ "$inst" == zimm* ]]; then
			imm="${inst%%m*}"
			imm="${inst%%m*}m"
			inst="${inst#*m}"
			inst="${inst#*m}"
			l=$((5))
			len=$((${len} - ${l}))
# 			echo ${imm} and ${inst} $l remaining ${len}
			define_shift $name ZIMM $len
			define_mask $name ZIMM $l $len
		fi
		# bits
		if [[ "$inst" == 0* || "$inst" == 1* ]]; then
			_inst=$(echo ${inst} | sed 's/^[0-9]*//')
			imm=$(echo ${inst} | sed 's/\(^[0-1]*\)/\1 /g' | awk '{print $1}' )
			inst=$(echo ${inst} | sed 's/^[0-9]*//')
			l=$(( $(echo ${imm} | wc -c) - 1))
			len=$((${len} - ${l} ))
			define_opcode $name${opcode_cnt} $imm $len
			opcode_cnt=$(($opcode_cnt + 1))
# 			echo $_inst and  ${imm} and ${inst} $l remaining ${len}
		fi
		if [[ ${len} -eq 0 ]]; then
 			echo "$name - ${inst} is done"
			define_opcode_merge $name $opcode_cnt
			break;
		fi
	done
}

o="../include/riscv_insc.h"

echo "#ifndef  __RISCV_INSC_H__" > $o
echo "#define  __RISCV_INSC_H__" >> $o
echo "" >> $o
echo "// generated file" >> $o
echo "" >> $o

input="../data/instructionset.txt"
while IFS= read -r line
do
# 	echo "$line"
	parse "$line"
done < "$input"
echo "#endif" >> $o
