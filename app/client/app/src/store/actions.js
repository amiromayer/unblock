import Vue from 'vue'
import backend from './backend'

export default {

    fetchResourceOne: function  (context) {
        backend.fetchResourceOne().then((responseData) => {
          context.commit('setResource', responseData)
        })
    },

    fetchResourceTwo: function  (context, resourceId) {
         // console.log(resourceId);
        backend.fetchResourceTwo(resourceId).then((responseData) => {
            context.commit('setResource', responseData)
        })
    },

    getPublicKey: function(context, masterPubKey){
        backend.getPublicKey(masterPubKey).then((responseData) => {
            context.commit('setPublicKey', responseData)
        })
    },

    getExtendedKeys: function(context, seed) {
        backend.getExtendedKeys(seed).then((responseData) => {
            context.commit('setExtendedKeys', responseData)
        })
    },

}
