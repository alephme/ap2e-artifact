// Field/point vector algebra — trimmed + de-globalized port from
// anonymous-zether packages/anonymous.js/src/utils/algebra.js.
//
// De-globalization: the mutable PedersenVectorCommitment.base global (which the
// reference InnerProductProof mutated during recursion) is eliminated entirely.
// Vector commitments are built directly via PointVector.multiExponentiate on
// explicitly-passed generator vectors. PedersenCommitment.base is kept, but it is
// immutable derived state (g = mapInto("G"), h = mapInto("H")) and is never mutated.
const BN = require('bn.js');

const bn128 = require('./bn128.js');
const utils = require('./utils.js');
const { soliditySha3Packed } = require('./keccak.js');

class PedersenCommitment {
    static base = {
        'g': utils.mapInto(soliditySha3Packed("G")),
        'h': utils.mapInto(soliditySha3Packed("H")),
    }

    constructor(point) {
        this._commit = (value, randomness) => { // both args are already-reduced BNs
            this.randomness = randomness;
            point = PedersenCommitment.base['g'].mul(value).add(PedersenCommitment.base['h'].mul(randomness));
        };
        this.point = () => point;
    }

    static commit(value) { // an already-reduced BN
        const result = new PedersenCommitment(bn128.zero);
        result._commit(value, bn128.randomScalar());
        return result;
    }
}

class FieldVector {
    constructor(vector) {
        this.getVector = () => vector;
        this.length = () => vector.length;
        this.slice = (begin, end) => new FieldVector(vector.slice(begin, end));
        this.flip = () => new FieldVector(Array.from({ length: this.length() }).map((_, i) => vector[(this.length() - i) % this.length()]));
        this.extract = (parity) => new FieldVector(vector.filter((_, i) => i % 2 === parity));
        this.add = (other) => new FieldVector(other.getVector().map((elem, i) => vector[i].redAdd(elem)))
        this.negate = () => new FieldVector(vector.map((elem) => elem.redNeg()));
        this.plus = (constant) => new FieldVector(vector.map((elem) => elem.redAdd(constant)));
        this.push = (constant) => { vector.push(constant); };
        this.sum = () => vector.reduce((accum, cur) => accum.redAdd(cur), new BN(0).toRed(bn128.q));
        this.hadamard = (other) => new FieldVector(other.getVector().map((elem, i) => vector[i].redMul(elem)));
        this.invert = () => new FieldVector(vector.map((elem) => elem.redInvm()));
        this.times = (constant) => new FieldVector(vector.map((elem) => elem.redMul(constant)));
        this.innerProduct = (other) => other.getVector().reduce((accum, cur, i) => accum.redAdd(vector[i].redMul(cur)), new BN(0).toRed(bn128.q));
        this.concat = (other) => new FieldVector(vector.concat(other.getVector()));
    }
}

class PointVector {
    constructor(vector) {
        this.getVector = () => vector;
        this.length = () => vector.length;
        this.slice = (begin, end) => new PointVector(vector.slice(begin, end));
        this.flip = () => new PointVector(Array.from({ length: this.length() }).map((_, i) => vector[(this.length() - i) % this.length()]));
        this.extract = (parity) => new PointVector(vector.filter((_, i) => i % 2 === parity));
        this.negate = () => new PointVector(vector.map((elem) => elem.neg()));
        this.multiExponentiate = (exponents) => exponents.getVector().reduce((accum, cur, i) => accum.add(vector[i].mul(cur)), bn128.zero);
        this.sum = () => vector.reduce((accum, cur) => accum.add(cur), bn128.zero);
        this.add = (other) => new PointVector(other.getVector().map((elem, i) => vector[i].add(elem)));
        this.hadamard = (exponents) => new PointVector(exponents.getVector().map((elem, i) => vector[i].mul(elem)));
        this.times = (constant) => new PointVector(vector.map((elem) => elem.mul(constant)));
        this.concat = (other) => new PointVector(vector.concat(other.getVector()));
    }
}

module.exports = { PedersenCommitment, FieldVector, PointVector };
