import Vue from 'vue'

export default {

    setLoading: function (state, bool) {
      state.isLoading = bool
    },

    setResource: function (state, value) {
      state.resource = value
    },

    setPublicKey: function(state, value){
      state.publicKey = value;
    },

    setExtendedKeys: function(state, value){
        state.extended_keys = value;
    }
}

