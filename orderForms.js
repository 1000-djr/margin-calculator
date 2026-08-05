/**
 * orderForms.js
 * 도매처별 발주 엑셀 양식 정의.
 * 각 source 값 의미:
 *   'recipient_name'    수령인 이름
 *   'recipient_phone'   수령인 전화번호
 *   'recipient_address' 수령인 주소
 *   'recipient_zipcode' 수령인 우편번호
 *   'product_name'      도매처 상품명 (발주 매칭의 supplier_product_name)
 *   'option_name'       도매처 옵션명 (발주 매칭의 supplier_option_name)
 *   'qty'               수량
 *   'delivery_msg'      배송 메시지
 *   'sender_name'       보내는사람 이름 (사용자 설정값)
 *   'sender_phone'      보내는사람 전화번호 (사용자 설정값)
 *   'sender_address'    보내는사람 주소 (사용자 설정값)
 *   'order_number'      쿠팡 주문번호
 *   'empty'             빈칸
 */

const ORDER_FORMS = {
  // 더그린: 시트명 '양식', 헤더 1행
  thegreen: {
    label: '더그린',
    sheet: '양식',
    columns: [
      { header: '주문번호',              source: 'order_number' },
      { header: '주문자명',              source: 'sender_name' },
      { header: '주문자연락처',          source: 'sender_phone' },
      { header: '보내는사람 주소',       source: 'sender_address' },
      { header: '수령인',               source: 'recipient_name' },
      { header: '수령인 연락처',         source: 'recipient_phone' },
      { header: '수령인 주소 (받는사람)', source: 'recipient_address' },
      { header: '상품명',               source: 'product_name' },
      { header: '수량',                 source: 'qty' },
      { header: '옵션명',               source: 'option_name' },
      { header: '배송메세지',            source: 'delivery_msg' },
    ],
  },

  // 늘푸른우리: 시트명 'Sheet1'
  neulpureun: {
    label: '늘푸른우리',
    sheet: 'Sheet1',
    columns: [
      { header: '제품명',                    source: 'product_name' },
      { header: '옵션명(옵션 없을시 공란)',   source: 'option_name' },
      { header: '수량',                      source: 'qty' },
      { header: '수령인',                    source: 'recipient_name' },
      { header: '우편번호',                  source: 'recipient_zipcode' },
      { header: ' 주  소',                   source: 'recipient_address' },
      { header: '전화번호',                  source: 'recipient_phone' },
      { header: '배송메세지',                source: 'delivery_msg' },
      { header: '업체명(필수)',               source: 'sender_name' },
      { header: '업체주소(필수)',             source: 'sender_address' },
      { header: '업체전화(필수)',             source: 'sender_phone' },
      { header: '주문번호(없을시 공란)',       source: 'order_number' },
    ],
  },

  // 에코앤팜: 시트명 'Sheet1'
  ecofarm: {
    label: '에코앤팜',
    sheet: 'Sheet1',
    columns: [
      { header: '수령인',                    source: 'recipient_name' },
      { header: '수령인\n전화번호',           source: 'recipient_phone' },
      { header: '전화번호2',                 source: 'empty' },
      { header: '우편번호',                  source: 'recipient_zipcode' },
      { header: '수령인 주소',               source: 'recipient_address' },
      { header: '보내는사람\n(업체명)',        source: 'sender_name' },
      { header: '전화번호\n(업체 전화번호)',   source: 'sender_phone' },
      { header: '우편번호(지정)',             source: 'empty' },
      { header: '보내시는분 주소',            source: 'sender_address' },
      { header: '주문 수량',                 source: 'qty' },
      { header: '수량b',                    source: 'empty' },
      { header: '수량c',                    source: 'empty' },
      { header: '운임',                     source: 'empty' },
      { header: '상품명',                   source: 'product_name' },
      { header: '특기사항',                  source: 'empty' },
      { header: '배송메시지',                source: 'delivery_msg' },
      { header: '상품주문번호',              source: 'order_number' },
    ],
  },

  // 정다운영농조합법인: 시트명 'Sheet1' (발주오라 연동 시 거래처명으로 동적 변경 가능)
  jungdaun: {
    label: '정다운영농조합법인',
    sheet: 'Sheet1',
    columns: [
      { header: '매출처 주문번호',           source: 'order_number' },
      { header: '주문자 명',                source: 'sender_name' },
      { header: '주문자 연락처',             source: 'sender_phone' },
      { header: '주문자 추가 연락처',        source: 'empty' },
      { header: '공란',                     source: 'empty' },
      { header: '주문자주소',               source: 'sender_address' },
      { header: '수령자 명',                source: 'recipient_name' },
      { header: '수령자 연락처',             source: 'recipient_phone' },
      { header: '수령자 추가 연락처',        source: 'empty' },
      { header: '우편번호',                 source: 'recipient_zipcode' },
      { header: '주소',                     source: 'recipient_address' },
      { header: '상품명',                   source: 'product_name' },
      { header: '공란',                     source: 'empty' },
      { header: '수량',                     source: 'qty' },
      { header: '배송메모',                 source: 'delivery_msg' },
    ],
  },

  // 랑(TCG): 시트명 'Sheet1'
  rang: {
    label: '랑',
    sheet: 'Sheet1',
    columns: [
      { header: '수취인',                   source: 'recipient_name' },
      { header: '전화번호',                 source: 'recipient_phone' },
      { header: '주소',                     source: 'recipient_address' },
      { header: '품목',                     source: 'product_name' },
      { header: '수량',                     source: 'qty' },
      { header: '배송메세지',               source: 'delivery_msg' },
      { header: '보내는분',                 source: 'sender_name' },
      { header: '보내는분 전화번호',         source: 'sender_phone' },
      { header: '보내는 분 주소',           source: 'sender_address' },
    ],
  },
};

module.exports = { ORDER_FORMS };
