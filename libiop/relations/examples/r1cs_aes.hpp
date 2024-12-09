/** @file
 *****************************************************************************
 Declaration of interfaces for AES R1CS examples
 *****************************************************************************
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RELATIONS__EXAMPLES__R1CS_AES_HPP_
#define RELATIONS__EXAMPLES__R1CS_AES_HPP_

#include "libiop/relations/r1cs.hpp"
#include "libiop/relations/examples/r1cs_examples.hpp"

namespace libiop {

/**
 * Generate an R1CS example for AES-128 encryption
 */
template<typename FieldT>
r1cs_example<FieldT> generate_aes_r1cs_example();

} // libiop

#include "libiop/relations/examples/r1cs_aes.tcc"

#endif // RELATIONS__EXAMPLES__R1CS_AES_HPP_
