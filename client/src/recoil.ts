import { atom, useRecoilState } from "recoil";

export const accessTokenState = atom<string>({
    key: 'accessTokenState',
    default: '',
});